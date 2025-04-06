from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import hmac
import hashlib
import json
from typing import Optional
import logging
import requests  # Added for GitHub API calls
from github import Github  # Added for GitHub API client
import os

from dotenv import load_dotenv
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="GitHub Webhook Handler",
    description="API to handle GitHub webhooks",
    version="1.0.0"
)

# Replace these with your actual secrets
GITHUB_WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN")

# Initialize GitHub client
github_client = Github(GITHUB_ACCESS_TOKEN)

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify GitHub webhook signature
    """
    if not signature:
        return False
    
    secret_bytes = bytes(secret, 'utf-8')
    mac = hmac.new(secret_bytes, msg=payload, digestmod=hashlib.sha256)
    expected_signature = f"sha256={mac.hexdigest()}"
    
    return hmac.compare_digest(expected_signature, signature)

def get_pr_diff(repo_name: str, pr_number: int) -> str:
    """
    Fetch the diff for a specific pull request
    """
    try:
        repo = github_client.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        # Get the diff URL from the PR
        diff_url = pr.diff_url
        
        # Make a direct request to get the diff
        headers = {
            "Accept": "application/vnd.github.v3.diff",
            "Authorization": f"token {GITHUB_ACCESS_TOKEN}"
        }
        
        response = requests.get(diff_url, headers=headers)
        response.raise_for_status()
        
        return response.text
    except Exception as e:
        logger.error(f"Error fetching PR diff: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching PR diff: {str(e)}"
        )

@app.post("/webhook")
async def handle_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None)
):
    """
    Handle incoming GitHub webhooks
    """
    try:
        payload = await request.body()
        
        if not verify_signature(
            payload=payload,
            signature=x_hub_signature_256,
            secret=GITHUB_WEBHOOK_SECRET
        ):
            logger.warning("Invalid signature received")
            raise HTTPException(
                status_code=401,
                detail="Invalid signature"
            )

        try:
            event_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError:
            logger.error("Invalid JSON payload")
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON payload"
            )

        if not x_github_event:
            logger.warning("Missing X-GitHub-Event header")
            raise HTTPException(
                status_code=400,
                detail="Missing X-GitHub-Event header"
            )

        logger.info(f"Received {x_github_event} event")

        if x_github_event == "ping":
            return handle_ping_event(event_data)
        elif x_github_event == "push":
            return await handle_push_event(event_data)
        elif x_github_event == "pull_request":
            return await handle_pull_request_event(event_data)
        else:
            logger.info(f"Unhandled event type: {x_github_event}")
            return JSONResponse(
                status_code=200,
                content={"message": f"Unhandled event type: {x_github_event}"}
            )

    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

def handle_ping_event(event_data: dict):
    """
    Handle ping event from GitHub
    """
    logger.info(f"Ping event received: {event_data.get('zen', 'No zen message')}")
    return JSONResponse(
        status_code=200,
        content={
            "message": "Ping received successfully",
            "zen": event_data.get("zen")
        }
    )

async def handle_push_event(event_data: dict):
    """
    Handle push event from GitHub
    """
    try:
        repo_name = event_data.get("repository", {}).get("full_name", "unknown")
        pusher = event_data.get("pusher", {}).get("name", "unknown")
        commits = len(event_data.get("commits", []))
        
        logger.info(f"Push event to {repo_name} by {pusher} with {commits} commits")
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Push event processed successfully",
                "repository": repo_name,
                "pusher": pusher,
                "commits": commits
            }
        )
    except Exception as e:
        logger.error(f"Error handling push event: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error processing push event"
        )

async def handle_pull_request_event(event_data: dict):
    """
    Handle pull request event from GitHub
    """
    try:
        action = event_data.get("action", "unknown")
        repo_name = event_data.get("repository", {}).get("full_name", "unknown")
        pr_number = event_data.get("pull_request", {}).get("number", "unknown")
        pr_title = event_data.get("pull_request", {}).get("title", "unknown")
        
        logger.info(f"Pull request {action} #{pr_number} in {repo_name}")
        
        # Get the diff if the PR is opened or synchronized
        diff = None
        if action in ["opened", "synchronize"]:
            diff = get_pr_diff(repo_name, pr_number)
        
        print(diff)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Pull request event processed successfully",
                "repository": repo_name,
                "action": action,
                "pr_number": pr_number,
                "pr_title": pr_title,
            }
        )
    except Exception as e:
        logger.error(f"Error handling pull request event: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error processing pull request event"
        )

@app.get("/")
async def root():
    """
    Health check endpoint
    """
    return {"message": "GitHub Webhook Handler is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
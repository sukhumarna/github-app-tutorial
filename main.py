from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import hmac
import hashlib
import json
from typing import Optional, List, Dict
import logging
import requests
from github import Github
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="GitHub Webhook Handler",
    description="API to handle GitHub webhooks",
    version="1.0.0"
)

# Replace these with your actual secrets
GITHUB_WEBHOOK_SECRET = "your-webhook-secret-token-here"
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN", "your-github-access-token-here")

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

def parse_diff_by_file(diff_text: str) -> List[Dict[str, str]]:
    """
    Parse the diff text and split it by file
    Returns list of dicts with file name and its diff
    """
    if not diff_text:
        return []

    try:
        result = []
        current_file = None
        current_diff = []
        lines = diff_text.split('\n')

        for line in lines:
            # Check for new file diff start
            if line.startswith('diff --git'):
                # Save previous file diff if exists
                if current_file and current_diff:
                    result.append({
                        "file": current_file,
                        "pr_diff": '\n'.join(current_diff)
                    })
                
                # Reset for new file
                current_diff = [line]
                
                # Try to extract file name from next lines
                for next_line in lines[lines.index(line):]:
                    if next_line.startswith('--- a/'):
                        current_file = next_line[6:]  # Remove '--- a/'
                        break
                    elif next_line.startswith('+++ b/'):
                        current_file = next_line[6:]  # Remove '+++ b/'
                        break
            elif current_diff:  # Continue collecting diff lines
                current_diff.append(line)

        # Add the last file
        if current_file and current_diff:
            result.append({
                "file": current_file,
                "pr_diff": '\n'.join(current_diff)
            })

        return result
    except Exception as e:
        logger.error(f"Error parsing diff: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error parsing diff: {str(e)}"
        )

def get_pr_diff(repo_name: str, pr_number: int) -> List[Dict[str, str]]:
    """
    Fetch the diff for a specific pull request and split by file
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
        
        # Parse the diff by file
        return parse_diff_by_file(response.text)
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
        pr_diffs = []
        if action in ["opened", "synchronize"]:
            pr_diffs = get_pr_diff(repo_name, pr_number)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Pull request event processed successfully",
                "repository": repo_name,
                "action": action,
                "pr_number": pr_number,
                "pr_title": pr_title,
                "pr_diffs": pr_diffs if pr_diffs else []
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
"""
Gmail OAuth2 authentication module.

Handles the full OAuth2 flow for Gmail API access:
- Loads credentials from credentials.json
- Enforces READONLY scope only (security: agent can never send/delete/modify emails)
- Caches token to token.json; auto-refreshes expired tokens
- Can be run standalone to complete the initial OAuth flow
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

load_dotenv()

# SECURITY: Read-only scope — the agent can NEVER send, delete, or modify emails
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_credentials(
    credentials_path: str | None = None,
    token_path: str | None = None,
) -> Credentials:
    """
    Obtain valid Gmail API credentials.

    1. If token.json exists and is valid, use it.
    2. If token is expired but has a refresh_token, refresh it.
    3. Otherwise, run the full OAuth flow (opens browser).

    Returns:
        google.oauth2.credentials.Credentials
    """
    credentials_path = credentials_path or os.getenv(
        "GOOGLE_CREDENTIALS_PATH", "./credentials.json"
    )
    token_path = token_path or os.getenv("GOOGLE_TOKEN_PATH", "./token.json")

    creds = None

    # Step 1: Try loading existing token
    if Path(token_path).exists():
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    # Step 2: Refresh or re-authenticate
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        _save_token(creds, token_path)
    elif not creds or not creds.valid:
        if not Path(credentials_path).exists():
            raise FileNotFoundError(
                f"credentials.json not found at {credentials_path}. "
                "Download it from Google Cloud Console → APIs & Services → Credentials."
            )
        flow = InstalledAppFlow.from_client_secrets_file(
            credentials_path, SCOPES
        )
        creds = flow.run_local_server(port=3456)
        _save_token(creds, token_path)

    return creds


def _save_token(creds: Credentials, token_path: str) -> None:
    """Persist token to disk for future runs."""
    with open(token_path, "w") as f:
        f.write(creds.to_json())


def run_auth_flow() -> None:
    """Run the OAuth flow interactively (for standalone use)."""
    from rich.console import Console

    console = Console()
    console.print("[bold]Gmail OAuth2 Authentication[/bold]\n")
    console.print("Scope: [green]gmail.readonly[/green] (read-only access)")
    console.print("This will open your browser to authenticate with Google.\n")

    try:
        creds = get_credentials()
        console.print("[bold green]Authentication successful![/bold green]")
        console.print(f"Token saved to: {os.getenv('GOOGLE_TOKEN_PATH', './token.json')}")
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]Authentication failed:[/bold red] {e}")

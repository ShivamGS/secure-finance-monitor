"""
Standalone script to run Gmail OAuth2 authentication.

Usage:
    python -m src.mcp_server.gmail_auth_runner

This will open your browser, complete the Google OAuth flow,
and save the token to token.json for future use.
"""

from .gmail_auth import run_auth_flow

if __name__ == "__main__":
    run_auth_flow()

"""
Centralized configuration — all settings in one place.
Loads from environment variables with sensible defaults.
"""

from dataclasses import dataclass
from typing import Optional
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class Config:
    """Central configuration for the secure finance monitor."""

    # LLM
    model_provider: str
    model_name: str
    openai_api_key: Optional[str]
    anthropic_api_key: Optional[str]

    # Gmail
    google_credentials_path: str
    google_token_path: str

    # Storage
    db_path: str
    db_encryption_key: Optional[str]
    audit_log_path: str

    # Agent behavior
    scan_days: int
    max_emails_per_scan: int

    # Security
    fail_closed: bool
    enable_response_sanitization: bool

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables with sensible defaults."""

        # Auto-detect model provider based on available API keys
        openai_key = os.getenv("OPENAI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")

        provider = os.getenv("MODEL_PROVIDER", "").lower()
        if not provider:
            # Auto-detect: check which API key is available
            if openai_key:
                provider = "openai"
            elif anthropic_key:
                provider = "anthropic"
            else:
                provider = "mock"

        return cls(
            # LLM
            model_provider=provider,
            model_name=os.getenv("MODEL_NAME", "gpt-4o-mini"),
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,

            # Gmail
            google_credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH", "./credentials.json"),
            google_token_path=os.getenv("GOOGLE_TOKEN_PATH", "./token.json"),

            # Storage
            db_path=os.getenv("DB_PATH", "finance_monitor.db"),
            db_encryption_key=os.getenv("DB_ENCRYPTION_KEY"),
            audit_log_path=os.getenv("AUDIT_LOG_PATH", "audit.jsonl"),

            # Agent behavior
            scan_days=int(os.getenv("SCAN_DAYS", "30")),
            max_emails_per_scan=int(os.getenv("MAX_EMAILS_PER_SCAN", "100")),

            # Security
            fail_closed=os.getenv("FAIL_CLOSED", "true").lower() == "true",
            enable_response_sanitization=os.getenv("ENABLE_RESPONSE_SANITIZATION", "true").lower() == "true",
        )

    def has_gmail_credentials(self) -> bool:
        """Check if Gmail OAuth credentials file exists."""
        return os.path.exists(self.google_credentials_path)

    def has_gmail_token(self) -> bool:
        """Check if Gmail OAuth token exists."""
        return os.path.exists(self.google_token_path)

    def has_llm_api_key(self) -> bool:
        """Check if any LLM API key is configured."""
        return bool(self.openai_api_key or self.anthropic_api_key)

"""
Email blocklist system for filtering promotional/non-financial emails.

This is the first security layer before PII redaction. Blocks known
promotional senders and marketing domains to reduce processing overhead.
"""

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Blocklist:
    """
    Singleton email blocklist manager.

    Loads blocked senders, domains, and subject patterns from config/blocklist.json.
    Provides fast matching and statistics tracking for the demo.
    """

    _instance: Optional['Blocklist'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.blocked_senders: set[str] = set()
        self.blocked_domains: set[str] = set()
        self.blocked_subject_patterns: list[str] = []

        # Statistics for demo display
        self._total_checks = 0
        self._blocked_count = 0
        self._blocked_by_sender = 0
        self._blocked_by_domain = 0
        self._blocked_by_subject = 0

        # Load configuration
        self._load_config()

    def _load_config(self) -> None:
        """Load blocklist from config/blocklist.json. Fail-open if missing."""
        config_path = Path(__file__).parent.parent.parent / "config" / "blocklist.json"

        if not config_path.exists():
            logger.warning(f"Blocklist config not found at {config_path} - allowing all emails (fail-open)")
            return

        try:
            with open(config_path, 'r') as f:
                data = json.load(f)

            # Load blocked senders (case-insensitive)
            self.blocked_senders = {s.lower() for s in data.get("blocked_senders", [])}

            # Load blocked domains (case-insensitive)
            self.blocked_domains = {d.lower() for d in data.get("blocked_domains", [])}

            # Load subject patterns (case-insensitive matching)
            self.blocked_subject_patterns = [p.lower() for p in data.get("blocked_subject_patterns", [])]

            logger.info(
                f"Loaded blocklist: {len(self.blocked_senders)} senders, "
                f"{len(self.blocked_domains)} domains, "
                f"{len(self.blocked_subject_patterns)} subject patterns"
            )

        except Exception as e:
            logger.error(f"Failed to load blocklist config: {e} - allowing all emails (fail-open)")

    def is_blocked(self, sender: str, subject: str) -> tuple[bool, str]:
        """
        Check if email should be blocked.

        Args:
            sender: Email sender address (e.g., "noreply@groupon.com")
            subject: Email subject line

        Returns:
            (is_blocked: bool, reason: str)
            - (True, "sender") if sender is blocked
            - (True, "domain") if sender domain is blocked
            - (True, "subject") if subject contains blocked pattern
            - (False, "") if email is allowed
        """
        self._total_checks += 1

        sender_lower = sender.lower()
        subject_lower = subject.lower()

        # Check exact sender match
        if sender_lower in self.blocked_senders:
            self._blocked_count += 1
            self._blocked_by_sender += 1
            return (True, "sender")

        # Check domain match
        # Extract domain from sender: "Name <email@domain.com>" or "email@domain.com"
        if '@' in sender_lower:
            email_part = sender_lower.split('<')[-1].strip('>')
            domain = email_part.split('@')[-1].strip()

            if domain in self.blocked_domains:
                self._blocked_count += 1
                self._blocked_by_domain += 1
                return (True, "domain")

        # Check subject patterns (substring matching)
        for pattern in self.blocked_subject_patterns:
            if pattern in subject_lower:
                self._blocked_count += 1
                self._blocked_by_subject += 1
                return (True, "subject")

        return (False, "")

    def reload(self) -> None:
        """Reload blocklist configuration from disk."""
        logger.info("Reloading blocklist configuration...")

        # Clear existing data
        self.blocked_senders.clear()
        self.blocked_domains.clear()
        self.blocked_subject_patterns.clear()

        # Reload from config file
        self._load_config()

    def stats(self) -> dict:
        """
        Get blocklist statistics for demo display.

        Returns:
            Dictionary with statistics:
            {
                "total_checks": int,
                "blocked_count": int,
                "blocked_by_sender": int,
                "blocked_by_domain": int,
                "blocked_by_subject": int,
                "block_rate": float (percentage)
            }
        """
        block_rate = (self._blocked_count / self._total_checks * 100) if self._total_checks > 0 else 0.0

        return {
            "total_checks": self._total_checks,
            "blocked_count": self._blocked_count,
            "blocked_by_sender": self._blocked_by_sender,
            "blocked_by_domain": self._blocked_by_domain,
            "blocked_by_subject": self._blocked_by_subject,
            "block_rate": round(block_rate, 1),
            "config_loaded": bool(self.blocked_senders or self.blocked_domains or self.blocked_subject_patterns)
        }

    def reset_stats(self) -> None:
        """Reset statistics counters (useful for testing/demo)."""
        self._total_checks = 0
        self._blocked_count = 0
        self._blocked_by_sender = 0
        self._blocked_by_domain = 0
        self._blocked_by_subject = 0


# Singleton instance
_blocklist_instance = Blocklist()


def get_blocklist() -> Blocklist:
    """Get the singleton blocklist instance."""
    return _blocklist_instance

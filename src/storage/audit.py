"""
Tamper-evident audit logger with hash chaining.

Writes every action to BOTH:
1. The encrypted SQLite database (for querying)
2. A local JSONL file (human-readable backup)

Each entry includes a SHA-256 hash of (previous_hash + entry_data),
creating a hash chain. If anyone tampers with an entry, the chain breaks.
Entries are append-only — never modified or deleted.
"""

import hashlib
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .database import EncryptedDatabase
from .models import AuditEntry

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only audit logger with hash chain integrity."""

    def __init__(
        self,
        database: EncryptedDatabase,
        log_file: str = "audit_log.jsonl",
        suppress_stderr: bool = False,
    ) -> None:
        self._db = database
        self._log_path = Path(log_file)
        self._previous_hash = self._load_last_hash()
        self._suppress_stderr = suppress_stderr

    def _load_last_hash(self) -> str:
        """Load the hash of the last entry for chain continuity."""
        entries = self._db.get_audit_entries(count=1)
        if entries:
            return entries[0].entry_hash
        return "GENESIS"

    def _compute_hash(self, entry: AuditEntry, previous_hash: str) -> str:
        """Compute SHA-256 hash for chain integrity."""
        data = (
            f"{previous_hash}|{entry.id}|{entry.timestamp.isoformat()}|"
            f"{entry.action}|{entry.tool_used}|{entry.details}|"
            f"{entry.redactions_applied}|{entry.security_flags}|{entry.level}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def log(
        self,
        action: str,
        tool_used: str = "",
        details: str = "",
        redactions: int = 0,
        security_flags: int = 0,
        level: str = "INFO",
    ) -> AuditEntry:
        """
        Create an audit entry, save to DB and JSONL file.

        Args:
            action: What happened (e.g. "fetch_emails", "categorize")
            tool_used: Which tool was invoked
            details: Human-readable description (NO PII)
            redactions: Number of PII items redacted
            security_flags: Number of injection attempts detected
            level: INFO, WARNING, or CRITICAL
        """
        entry = AuditEntry(
            action=action,
            tool_used=tool_used,
            details=details,
            redactions_applied=redactions,
            security_flags=security_flags,
            level=level,
        )

        # Compute hash chain
        entry.previous_hash = self._previous_hash
        entry.entry_hash = self._compute_hash(entry, self._previous_hash)
        self._previous_hash = entry.entry_hash

        # Save to database
        self._db.save_audit_entry(entry)

        # Append to JSONL file
        self._append_to_file(entry)

        # CRITICAL events get printed to stderr (unless suppressed for demos)
        if level == "CRITICAL" and not self._suppress_stderr:
            self._print_critical(entry)

        return entry

    def log_scan_start(self, days: int, max_results: int) -> AuditEntry:
        return self.log(
            action="scan_start",
            tool_used="fetch_financial_emails",
            details=f"Scan initiated: {days} days, max {max_results} emails",
        )

    def log_email_processed(
        self, email_id: str, redaction_count: int, had_injection: bool
    ) -> AuditEntry:
        level = "CRITICAL" if had_injection else "INFO"
        flags = 1 if had_injection else 0
        injection_note = " [PROMPT INJECTION DETECTED]" if had_injection else ""
        return self.log(
            action="email_processed",
            tool_used="pii_redactor",
            details=f"Email {email_id} processed: {redaction_count} redactions{injection_note}",
            redactions=redaction_count,
            security_flags=flags,
            level=level,
        )

    def log_categorization(
        self, merchant: str, amount: float, category: str
    ) -> AuditEntry:
        return self.log(
            action="categorize",
            tool_used="categorize_transaction",
            details=f"Categorized: {merchant} ${amount:.2f} -> {category}",
        )

    def log_anomaly_detected(
        self, anomaly_type: str, severity: str, description: str
    ) -> AuditEntry:
        level_map = {"low": "INFO", "medium": "WARNING", "high": "CRITICAL", "critical": "CRITICAL"}
        level = level_map.get(severity, "INFO")
        return self.log(
            action="anomaly_detected",
            tool_used="detect_anomalies",
            details=f"[{anomaly_type}/{severity}] {description}",
            level=level,
        )

    def log_response_sent(
        self, response_length: int, pii_found_in_output: bool
    ) -> AuditEntry:
        if pii_found_in_output:
            return self.log(
                action="response_sent",
                tool_used="response_sanitizer",
                details=f"Response ({response_length} chars) — PII FOUND AND REMOVED FROM OUTPUT",
                security_flags=1,
                level="CRITICAL",
            )
        return self.log(
            action="response_sent",
            tool_used="response_sanitizer",
            details=f"Response ({response_length} chars) — clean",
        )

    def log_security_event(self, event_type: str, details: str) -> AuditEntry:
        """Always CRITICAL level."""
        return self.log(
            action=f"security_event:{event_type}",
            tool_used="security_monitor",
            details=details,
            security_flags=1,
            level="CRITICAL",
        )

    def get_recent_entries(
        self, count: int = 50, level: str | None = None
    ) -> list[AuditEntry]:
        return self._db.get_audit_entries(count=count, level=level)

    def get_security_events(self, days: int = 7) -> list[AuditEntry]:
        """All CRITICAL entries in the last N days."""
        all_critical = self._db.get_audit_entries(count=1000, level="CRITICAL")
        cutoff = datetime.utcnow() - timedelta(days=days)
        return [e for e in all_critical if e.timestamp >= cutoff]

    def generate_audit_report(self, days: int = 7) -> dict:
        """Generate a summary report for a security auditor."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        # Get all entries in the period
        all_entries = self._db.get_audit_entries(count=10000)
        period_entries = [
            e for e in all_entries
            if e.timestamp.isoformat() >= cutoff
        ]

        total_redactions = sum(e.redactions_applied for e in period_entries)
        total_security_flags = sum(e.security_flags for e in period_entries)
        emails_processed = sum(1 for e in period_entries if e.action == "email_processed")
        anomalies_found = sum(1 for e in period_entries if e.action == "anomaly_detected")
        security_events = sum(1 for e in period_entries if e.level == "CRITICAL")

        actions_breakdown: dict[str, int] = {}
        for e in period_entries:
            actions_breakdown[e.action] = actions_breakdown.get(e.action, 0) + 1

        return {
            "period_days": days,
            "total_actions": len(period_entries),
            "emails_processed": emails_processed,
            "total_redactions": total_redactions,
            "anomalies_found": anomalies_found,
            "security_events": security_events,
            "total_security_flags": total_security_flags,
            "actions_breakdown": actions_breakdown,
            "chain_integrity": self.verify_integrity(),
        }

    def verify_integrity(self) -> bool:
        """
        Walk the hash chain and verify no entries have been tampered with.

        Returns True if the chain is intact, False if tampering detected.
        """
        entries = self._db.get_audit_entries(count=100000)

        if not entries:
            return True

        # Entries come back newest-first; reverse to walk oldest-first
        entries = list(reversed(entries))

        previous_hash = "GENESIS"
        for entry in entries:
            expected_hash = self._compute_hash(entry, previous_hash)
            if entry.entry_hash != expected_hash:
                logger.critical(
                    "AUDIT CHAIN BROKEN at entry %s: expected %s, got %s",
                    entry.id, expected_hash, entry.entry_hash,
                )
                return False
            if entry.previous_hash != previous_hash:
                logger.critical(
                    "AUDIT CHAIN BROKEN at entry %s: previous_hash mismatch",
                    entry.id,
                )
                return False
            previous_hash = entry.entry_hash

        return True

    def _append_to_file(self, entry: AuditEntry) -> None:
        """Append entry to JSONL file."""
        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        except OSError as e:
            logger.error("Failed to write audit log file: %s", e)

    @staticmethod
    def _print_critical(entry: AuditEntry) -> None:
        """Print CRITICAL events to stderr with formatting."""
        try:
            from rich.console import Console
            console = Console(stderr=True)
            console.print(
                f"[bold red]CRITICAL SECURITY EVENT[/bold red] "
                f"[{entry.timestamp.isoformat()}] {entry.action}: {entry.details}"
            )
        except ImportError:
            print(
                f"CRITICAL SECURITY EVENT [{entry.timestamp.isoformat()}] "
                f"{entry.action}: {entry.details}",
                file=sys.stderr,
            )

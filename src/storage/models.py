"""
Data models for the encrypted storage layer.

These models store ONLY financial metadata — never raw email content or PII.
source_email_id is a reference pointer; the actual email was discarded after redaction.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime


def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


@dataclass
class Transaction:
    id: str = field(default_factory=_new_id)
    date: datetime = field(default_factory=_now)
    merchant: str = ""
    amount: float = 0.0
    category: str = "Other"
    is_subscription: bool = False
    source_email_id: str = ""
    confidence: float = 0.0
    created_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["date"] = self.date.isoformat() if isinstance(self.date, datetime) else str(self.date)
        d["created_at"] = self.created_at.isoformat() if isinstance(self.created_at, datetime) else str(self.created_at)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        d = dict(data)
        for field_name in ("date", "created_at"):
            val = d.get(field_name)
            if isinstance(val, str):
                try:
                    d[field_name] = datetime.fromisoformat(val)
                except ValueError:
                    d[field_name] = _now()
        return cls(**d)


@dataclass
class Subscription:
    id: str = field(default_factory=_new_id)
    merchant: str = ""
    amount: float = 0.0
    frequency: str = "monthly"  # monthly, annual, weekly
    first_seen: datetime = field(default_factory=_now)
    last_seen: datetime = field(default_factory=_now)
    status: str = "active"  # active, cancelled, stale
    created_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        for f in ("first_seen", "last_seen", "created_at"):
            val = getattr(self, f)
            d[f] = val.isoformat() if isinstance(val, datetime) else str(val)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Subscription":
        d = dict(data)
        for f in ("first_seen", "last_seen", "created_at"):
            val = d.get(f)
            if isinstance(val, str):
                try:
                    d[f] = datetime.fromisoformat(val)
                except ValueError:
                    d[f] = _now()
        return cls(**d)


@dataclass
class Anomaly:
    id: str = field(default_factory=_new_id)
    type: str = ""  # DUPLICATE, SPIKE, NEW_MERCHANT, FREQUENCY, CATEGORY_SPIKE, SECURITY
    severity: str = "low"  # low, medium, high, critical
    description: str = ""
    transaction_ids: list[str] = field(default_factory=list)
    recommended_action: str = ""
    resolved: bool = False
    created_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat() if isinstance(self.created_at, datetime) else str(self.created_at)
        d["transaction_ids"] = json.dumps(self.transaction_ids)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Anomaly":
        d = dict(data)
        if isinstance(d.get("created_at"), str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                d["created_at"] = _now()
        tx_ids = d.get("transaction_ids", "[]")
        if isinstance(tx_ids, str):
            try:
                d["transaction_ids"] = json.loads(tx_ids)
            except (json.JSONDecodeError, TypeError):
                d["transaction_ids"] = []
        if isinstance(d.get("resolved"), int):
            d["resolved"] = bool(d["resolved"])
        return cls(**d)


@dataclass
class AuditEntry:
    id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_now)
    action: str = ""
    tool_used: str = ""
    details: str = ""
    redactions_applied: int = 0
    security_flags: int = 0
    level: str = "INFO"  # INFO, WARNING, CRITICAL
    entry_hash: str = ""
    previous_hash: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        d = dict(data)
        if isinstance(d.get("timestamp"), str):
            try:
                d["timestamp"] = datetime.fromisoformat(d["timestamp"])
            except ValueError:
                d["timestamp"] = _now()
        return cls(**d)

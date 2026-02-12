"""
Encrypted SQLite database for financial metadata storage.

Uses sqlcipher for encryption at rest. Falls back to regular sqlite3
if sqlcipher is unavailable (with a security warning).

SECURITY: Never stores raw email content or PII. Only extracted metadata:
merchant names, dollar amounts, dates, categories, and reference IDs.
"""

import logging
import os
import sqlite3
from datetime import datetime, timedelta

from dotenv import load_dotenv

from .models import Transaction, Subscription, Anomaly, AuditEntry

load_dotenv()
logger = logging.getLogger(__name__)

# Try sqlcipher first, fall back to sqlite3
_ENCRYPTED = False
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    _ENCRYPTED = True
except ImportError:
    sqlcipher = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    date TEXT NOT NULL,
    merchant TEXT NOT NULL,
    amount REAL NOT NULL,
    category TEXT NOT NULL DEFAULT 'Other',
    is_subscription INTEGER NOT NULL DEFAULT 0,
    source_email_id TEXT,
    confidence REAL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    merchant TEXT NOT NULL,
    amount REAL NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'monthly',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    description TEXT,
    transaction_ids TEXT DEFAULT '[]',
    recommended_action TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    tool_used TEXT,
    details TEXT,
    redactions_applied INTEGER DEFAULT 0,
    security_flags INTEGER DEFAULT 0,
    level TEXT NOT NULL DEFAULT 'INFO',
    entry_hash TEXT,
    previous_hash TEXT
);
"""


class EncryptedDatabase:
    """Encrypted SQLite database for financial metadata."""

    def __init__(
        self,
        db_path: str | None = None,
        encryption_key: str | None = None,
    ) -> None:
        self._db_path = db_path or os.getenv("DB_PATH", "finance_monitor.db")
        self._encryption_key = encryption_key or os.getenv("DB_ENCRYPTION_KEY", "")
        self._is_encrypted = False

        if _ENCRYPTED and sqlcipher and self._encryption_key:
            self._conn = sqlcipher.connect(self._db_path)
            self._conn.execute(f"PRAGMA key='{self._encryption_key}'")
            self._is_encrypted = True
            logger.info("Database opened with encryption (sqlcipher)")
        else:
            if not _ENCRYPTED or not sqlcipher:
                logger.warning(
                    "Database encryption unavailable — using unencrypted SQLite. "
                    "NOT suitable for production."
                )
            elif not self._encryption_key:
                logger.warning(
                    "DB_ENCRYPTION_KEY not set — using unencrypted SQLite. "
                    "NOT suitable for production."
                )
            self._conn = sqlite3.connect(self._db_path)

        self._conn.row_factory = sqlite3.Row if not self._is_encrypted else None
        self._create_tables()

    @property
    def is_encrypted(self) -> bool:
        return self._is_encrypted

    def _create_tables(self) -> None:
        """Create all tables if they don't exist."""
        for statement in _SCHEMA.split(";"):
            stmt = statement.strip()
            if stmt:
                self._conn.execute(stmt)
        self._conn.commit()

    # === Transactions ===

    def save_transaction(self, tx: Transaction) -> str:
        self._conn.execute(
            "INSERT OR REPLACE INTO transactions "
            "(id, date, merchant, amount, category, is_subscription, "
            "source_email_id, confidence, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tx.id,
                tx.date.isoformat() if isinstance(tx.date, datetime) else str(tx.date),
                tx.merchant,
                tx.amount,
                tx.category,
                int(tx.is_subscription),
                tx.source_email_id,
                tx.confidence,
                tx.created_at.isoformat() if isinstance(tx.created_at, datetime) else str(tx.created_at),
            ),
        )
        self._conn.commit()
        return tx.id

    def save_transactions_batch(self, txs: list[Transaction]) -> int:
        self._conn.execute("BEGIN")
        try:
            for tx in txs:
                self._conn.execute(
                    "INSERT OR REPLACE INTO transactions "
                    "(id, date, merchant, amount, category, is_subscription, "
                    "source_email_id, confidence, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tx.id,
                        tx.date.isoformat() if isinstance(tx.date, datetime) else str(tx.date),
                        tx.merchant,
                        tx.amount,
                        tx.category,
                        int(tx.is_subscription),
                        tx.source_email_id,
                        tx.confidence,
                        tx.created_at.isoformat() if isinstance(tx.created_at, datetime) else str(tx.created_at),
                    ),
                )
            self._conn.commit()
            return len(txs)
        except Exception:
            self._conn.rollback()
            raise

    def get_transactions(
        self,
        days: int = 30,
        category: str | None = None,
        merchant: str | None = None,
    ) -> list[Transaction]:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        query = "SELECT * FROM transactions WHERE date >= ?"
        params: list = [cutoff]

        if category:
            query += " AND category = ?"
            params.append(category)
        if merchant:
            query += " AND merchant LIKE ?"
            params.append(f"%{merchant}%")

        query += " ORDER BY date DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_transaction(r) for r in rows]

    def get_transaction_by_id(self, tx_id: str) -> Transaction | None:
        row = self._conn.execute(
            "SELECT * FROM transactions WHERE id = ?", (tx_id,)
        ).fetchone()
        return self._row_to_transaction(row) if row else None

    def clear_transactions(self) -> int:
        """Delete all transactions from the database. Returns number deleted."""
        count = self._conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        self._conn.execute("DELETE FROM transactions")
        self._conn.commit()
        return count

    # === Subscriptions ===

    def save_subscription(self, sub: Subscription) -> str:
        """Upsert: if merchant+amount exists, update last_seen instead of duplicating."""
        existing = self._conn.execute(
            "SELECT id FROM subscriptions WHERE merchant = ? AND amount = ? AND status = 'active'",
            (sub.merchant, sub.amount),
        ).fetchone()

        if existing:
            existing_id = existing[0] if isinstance(existing, tuple) else existing["id"]
            self._conn.execute(
                "UPDATE subscriptions SET last_seen = ? WHERE id = ?",
                (sub.last_seen.isoformat() if isinstance(sub.last_seen, datetime) else str(sub.last_seen), existing_id),
            )
            self._conn.commit()
            return existing_id

        self._conn.execute(
            "INSERT INTO subscriptions "
            "(id, merchant, amount, frequency, first_seen, last_seen, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sub.id,
                sub.merchant,
                sub.amount,
                sub.frequency,
                sub.first_seen.isoformat() if isinstance(sub.first_seen, datetime) else str(sub.first_seen),
                sub.last_seen.isoformat() if isinstance(sub.last_seen, datetime) else str(sub.last_seen),
                sub.status,
                sub.created_at.isoformat() if isinstance(sub.created_at, datetime) else str(sub.created_at),
            ),
        )
        self._conn.commit()
        return sub.id

    def get_active_subscriptions(self) -> list[Subscription]:
        rows = self._conn.execute(
            "SELECT * FROM subscriptions WHERE status = 'active' ORDER BY merchant"
        ).fetchall()
        return [self._row_to_subscription(r) for r in rows]

    def detect_stale_subscriptions(self, stale_days: int = 60) -> list[Subscription]:
        cutoff = (datetime.utcnow() - timedelta(days=stale_days)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM subscriptions WHERE status = 'active' AND last_seen < ?",
            (cutoff,),
        ).fetchall()
        subs = [self._row_to_subscription(r) for r in rows]

        # Mark them stale
        for sub in subs:
            self._conn.execute(
                "UPDATE subscriptions SET status = 'stale' WHERE id = ?",
                (sub.id,),
            )
        if subs:
            self._conn.commit()

        return subs

    # === Anomalies ===

    def save_anomaly(self, anomaly: Anomaly) -> str:
        import json as _json
        tx_ids = _json.dumps(anomaly.transaction_ids) if isinstance(anomaly.transaction_ids, list) else anomaly.transaction_ids
        self._conn.execute(
            "INSERT OR REPLACE INTO anomalies "
            "(id, type, severity, description, transaction_ids, "
            "recommended_action, resolved, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                anomaly.id,
                anomaly.type,
                anomaly.severity,
                anomaly.description,
                tx_ids,
                anomaly.recommended_action,
                int(anomaly.resolved),
                anomaly.created_at.isoformat() if isinstance(anomaly.created_at, datetime) else str(anomaly.created_at),
            ),
        )
        self._conn.commit()
        return anomaly.id

    def get_unresolved_anomalies(self) -> list[Anomaly]:
        rows = self._conn.execute(
            "SELECT * FROM anomalies WHERE resolved = 0 ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_anomaly(r) for r in rows]

    def resolve_anomaly(self, anomaly_id: str) -> bool:
        cur = self._conn.execute(
            "UPDATE anomalies SET resolved = 1 WHERE id = ?",
            (anomaly_id,),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # === Audit Log ===

    def save_audit_entry(self, entry: AuditEntry) -> str:
        self._conn.execute(
            "INSERT INTO audit_log "
            "(id, timestamp, action, tool_used, details, "
            "redactions_applied, security_flags, level, entry_hash, previous_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.id,
                entry.timestamp.isoformat() if isinstance(entry.timestamp, datetime) else str(entry.timestamp),
                entry.action,
                entry.tool_used,
                entry.details,
                entry.redactions_applied,
                entry.security_flags,
                entry.level,
                entry.entry_hash,
                entry.previous_hash,
            ),
        )
        self._conn.commit()
        return entry.id

    def get_audit_entries(
        self, count: int = 50, level: str | None = None
    ) -> list[AuditEntry]:
        query = "SELECT * FROM audit_log"
        params: list = []
        if level:
            query += " WHERE level = ?"
            params.append(level)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(count)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_audit_entry(r) for r in rows]

    # === Analytics ===

    def get_spending_by_category(self, days: int = 30) -> dict[str, float]:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        rows = self._conn.execute(
            "SELECT category, SUM(amount) as total "
            "FROM transactions WHERE date >= ? GROUP BY category "
            "ORDER BY total DESC",
            (cutoff,),
        ).fetchall()
        return {self._col(r, 0): round(self._col(r, 1) or 0.0, 2) for r in rows}

    def get_spending_trend(self, weeks: int = 4) -> list[dict]:
        result = []
        now = datetime.utcnow()
        for i in range(weeks):
            end = now - timedelta(weeks=i)
            start = end - timedelta(weeks=1)
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0) as total "
                "FROM transactions WHERE date >= ? AND date < ?",
                (start.isoformat(), end.isoformat()),
            ).fetchone()
            result.append({
                "week_start": start.isoformat()[:10],
                "week_end": end.isoformat()[:10],
                "transaction_count": self._col(row, 0) or 0,
                "total_spent": round(self._col(row, 1) or 0.0, 2),
            })
        return result

    def get_merchant_history(self, merchant: str) -> dict:
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0) as total, "
            "COALESCE(AVG(amount), 0) as avg_amt, MAX(date) as last_seen "
            "FROM transactions WHERE merchant LIKE ?",
            (f"%{merchant}%",),
        ).fetchone()
        return {
            "merchant": merchant,
            "total": round(self._col(row, 1) or 0.0, 2),
            "average": round(self._col(row, 2) or 0.0, 2),
            "count": self._col(row, 0) or 0,
            "last_seen": self._col(row, 3) or "",
        }

    # === Database Management ===

    def verify_encryption(self) -> bool:
        """
        Verify the database is actually encrypted.

        Tries to open the DB file with plain sqlite3 — if encrypted,
        this should fail to read any data.
        """
        if not self._is_encrypted:
            return False
        if self._db_path == ":memory:":
            return True  # in-memory encrypted DBs can't be tested this way

        try:
            test_conn = sqlite3.connect(self._db_path)
            test_conn.execute("SELECT count(*) FROM sqlite_master")
            test_conn.close()
            # If we get here, the DB is readable without a key = NOT encrypted
            return False
        except sqlite3.DatabaseError:
            # Can't read without key = encrypted!
            return True

    def get_stats(self) -> dict:
        stats = {}
        for table in ("transactions", "subscriptions", "anomalies", "audit_log"):
            row = self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = self._col(row, 0) or 0
        return stats

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    # === Row conversion helpers ===

    def _col(self, row, index_or_name):
        """Extract a column value from a row (works with both Row and tuple)."""
        if row is None:
            return None
        if isinstance(row, tuple):
            return row[index_or_name] if isinstance(index_or_name, int) else None
        try:
            return row[index_or_name]
        except (IndexError, KeyError, TypeError):
            return None

    def _row_to_transaction(self, row) -> Transaction:
        if isinstance(row, tuple):
            return Transaction(
                id=row[0], date=self._parse_dt(row[1]), merchant=row[2],
                amount=row[3], category=row[4], is_subscription=bool(row[5]),
                source_email_id=row[6] or "", confidence=row[7] or 0.0,
                created_at=self._parse_dt(row[8]),
            )
        return Transaction.from_dict(dict(row))

    def _row_to_subscription(self, row) -> Subscription:
        if isinstance(row, tuple):
            return Subscription(
                id=row[0], merchant=row[1], amount=row[2], frequency=row[3],
                first_seen=self._parse_dt(row[4]), last_seen=self._parse_dt(row[5]),
                status=row[6], created_at=self._parse_dt(row[7]),
            )
        return Subscription.from_dict(dict(row))

    def _row_to_anomaly(self, row) -> Anomaly:
        if isinstance(row, tuple):
            import json as _json
            tx_ids = row[4]
            if isinstance(tx_ids, str):
                try:
                    tx_ids = _json.loads(tx_ids)
                except (ValueError, TypeError):
                    tx_ids = []
            return Anomaly(
                id=row[0], type=row[1], severity=row[2], description=row[3],
                transaction_ids=tx_ids, recommended_action=row[5] or "",
                resolved=bool(row[6]), created_at=self._parse_dt(row[7]),
            )
        return Anomaly.from_dict(dict(row))

    def _row_to_audit_entry(self, row) -> AuditEntry:
        if isinstance(row, tuple):
            return AuditEntry(
                id=row[0], timestamp=self._parse_dt(row[1]), action=row[2],
                tool_used=row[3] or "", details=row[4] or "",
                redactions_applied=row[5] or 0, security_flags=row[6] or 0,
                level=row[7] or "INFO", entry_hash=row[8] or "",
                previous_hash=row[9] or "",
            )
        return AuditEntry.from_dict(dict(row))

    @staticmethod
    def _parse_dt(val) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except ValueError:
                pass
        return datetime.utcnow()

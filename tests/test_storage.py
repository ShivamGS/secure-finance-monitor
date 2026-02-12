"""
Comprehensive tests for encrypted storage and audit logging.

Database tests: encryption verification, CRUD, analytics, batch ops, fallback.
Audit tests: hash chain integrity, tamper detection, reporting, no PII in logs.
"""

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.storage.models import Transaction, Subscription, Anomaly, AuditEntry
from src.storage.database import EncryptedDatabase
from src.storage.audit import AuditLogger


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def tmp_db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def db(tmp_db_path):
    """Unencrypted DB for general testing."""
    database = EncryptedDatabase(db_path=tmp_db_path, encryption_key="")
    yield database
    database.close()


@pytest.fixture
def encrypted_db(tmp_path):
    """Encrypted DB for encryption-specific tests."""
    path = str(tmp_path / "encrypted_test.db")
    database = EncryptedDatabase(db_path=path, encryption_key="test-secret-key-123")
    yield database
    database.close()


@pytest.fixture
def auditor(db, tmp_path):
    log_file = str(tmp_path / "audit_test.jsonl")
    return AuditLogger(database=db, log_file=log_file)


def _make_transaction(**kwargs) -> Transaction:
    defaults = {
        "merchant": "Test Merchant",
        "amount": 42.99,
        "category": "Shopping",
        "date": datetime.utcnow(),
    }
    defaults.update(kwargs)
    return Transaction(**defaults)


def _make_subscription(**kwargs) -> Subscription:
    defaults = {
        "merchant": "Netflix",
        "amount": 15.99,
        "frequency": "monthly",
    }
    defaults.update(kwargs)
    return Subscription(**defaults)


# =====================================================================
# Model tests
# =====================================================================

class TestModels:
    """Test data model serialization/deserialization."""

    def test_transaction_round_trip(self):
        tx = _make_transaction(merchant="Starbucks", amount=5.45)
        d = tx.to_dict()
        restored = Transaction.from_dict(d)
        assert restored.merchant == "Starbucks"
        assert restored.amount == 5.45

    def test_subscription_round_trip(self):
        sub = _make_subscription()
        d = sub.to_dict()
        restored = Subscription.from_dict(d)
        assert restored.merchant == "Netflix"
        assert restored.amount == 15.99

    def test_anomaly_round_trip(self):
        a = Anomaly(type="DUPLICATE", severity="medium", transaction_ids=["t1", "t2"])
        d = a.to_dict()
        restored = Anomaly.from_dict(d)
        assert restored.type == "DUPLICATE"
        assert restored.transaction_ids == ["t1", "t2"]

    def test_audit_entry_round_trip(self):
        e = AuditEntry(action="test", level="INFO", details="something happened")
        d = e.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.action == "test"
        assert restored.level == "INFO"


# =====================================================================
# Encryption tests
# =====================================================================

class TestEncryption:
    """Test database encryption functionality."""

    def test_encrypted_db_is_encrypted(self, encrypted_db):
        assert encrypted_db.is_encrypted is True

    def test_unencrypted_db_reports_status(self, db):
        assert db.is_encrypted is False

    def test_verify_encryption_on_encrypted_db(self, encrypted_db):
        """Writing data then verifying: opening without key should fail."""
        tx = _make_transaction()
        encrypted_db.save_transaction(tx)
        assert encrypted_db.verify_encryption() is True

    def test_verify_encryption_on_unencrypted_db(self, db):
        assert db.verify_encryption() is False

    def test_encrypted_db_round_trip(self, encrypted_db):
        """Data survives write → close → reopen with same key."""
        tx = _make_transaction(merchant="EncryptTest", amount=99.99)
        encrypted_db.save_transaction(tx)

        # Reopen with same key
        path = encrypted_db._db_path
        encrypted_db.close()

        db2 = EncryptedDatabase(db_path=path, encryption_key="test-secret-key-123")
        retrieved = db2.get_transaction_by_id(tx.id)
        db2.close()

        assert retrieved is not None
        assert retrieved.merchant == "EncryptTest"
        assert retrieved.amount == 99.99


# =====================================================================
# Transaction CRUD tests
# =====================================================================

class TestTransactionCRUD:
    """Test transaction create/read operations."""

    def test_save_and_retrieve(self, db):
        tx = _make_transaction(merchant="Whole Foods", amount=127.43)
        db.save_transaction(tx)
        retrieved = db.get_transaction_by_id(tx.id)
        assert retrieved is not None
        assert retrieved.merchant == "Whole Foods"
        assert retrieved.amount == 127.43

    def test_get_nonexistent(self, db):
        assert db.get_transaction_by_id("nonexistent-id") is None

    def test_batch_save(self, db):
        txs = [_make_transaction(merchant=f"Merchant_{i}", amount=float(i)) for i in range(100)]
        count = db.save_transactions_batch(txs)
        assert count == 100
        stats = db.get_stats()
        assert stats["transactions"] == 100

    def test_filter_by_category(self, db):
        db.save_transaction(_make_transaction(merchant="Starbucks", category="Dining"))
        db.save_transaction(_make_transaction(merchant="Amazon", category="Shopping"))
        db.save_transaction(_make_transaction(merchant="Uber", category="Transport"))

        dining = db.get_transactions(days=1, category="Dining")
        assert len(dining) == 1
        assert dining[0].merchant == "Starbucks"

    def test_filter_by_merchant(self, db):
        db.save_transaction(_make_transaction(merchant="Whole Foods"))
        db.save_transaction(_make_transaction(merchant="Amazon"))

        results = db.get_transactions(days=1, merchant="Whole")
        assert len(results) == 1
        assert "Whole" in results[0].merchant

    def test_date_filtering(self, db):
        old = _make_transaction(merchant="OldTx", date=datetime.utcnow() - timedelta(days=60))
        new = _make_transaction(merchant="NewTx", date=datetime.utcnow())
        db.save_transaction(old)
        db.save_transaction(new)

        recent = db.get_transactions(days=7)
        merchants = [t.merchant for t in recent]
        assert "NewTx" in merchants
        assert "OldTx" not in merchants


# =====================================================================
# Subscription tests
# =====================================================================

class TestSubscriptions:
    """Test subscription CRUD and stale detection."""

    def test_save_and_retrieve(self, db):
        sub = _make_subscription()
        db.save_subscription(sub)
        active = db.get_active_subscriptions()
        assert len(active) == 1
        assert active[0].merchant == "Netflix"

    def test_upsert_updates_last_seen(self, db):
        sub1 = _make_subscription(merchant="Netflix", amount=15.99)
        db.save_subscription(sub1)

        sub2 = _make_subscription(merchant="Netflix", amount=15.99)
        sub2.last_seen = datetime.utcnow() + timedelta(days=30)
        returned_id = db.save_subscription(sub2)

        # Should have reused existing, not created duplicate
        active = db.get_active_subscriptions()
        assert len(active) == 1
        assert returned_id == sub1.id

    def test_different_amounts_not_upserted(self, db):
        sub1 = _make_subscription(merchant="Netflix", amount=15.99)
        sub2 = _make_subscription(merchant="Netflix", amount=22.99)
        db.save_subscription(sub1)
        db.save_subscription(sub2)

        active = db.get_active_subscriptions()
        assert len(active) == 2

    def test_detect_stale(self, db):
        old_sub = _make_subscription(merchant="OldService")
        old_sub.last_seen = datetime.utcnow() - timedelta(days=90)
        db.save_subscription(old_sub)

        new_sub = _make_subscription(merchant="NewService")
        db.save_subscription(new_sub)

        stale = db.detect_stale_subscriptions(stale_days=60)
        assert len(stale) == 1
        assert stale[0].merchant == "OldService"

        # After detection, status should be 'stale'
        active = db.get_active_subscriptions()
        assert len(active) == 1
        assert active[0].merchant == "NewService"


# =====================================================================
# Anomaly tests
# =====================================================================

class TestAnomalies:
    """Test anomaly CRUD and resolution."""

    def test_save_and_retrieve(self, db):
        anomaly = Anomaly(
            type="DUPLICATE", severity="medium",
            description="Possible duplicate", transaction_ids=["t1", "t2"],
        )
        db.save_anomaly(anomaly)
        unresolved = db.get_unresolved_anomalies()
        assert len(unresolved) == 1
        assert unresolved[0].type == "DUPLICATE"
        assert unresolved[0].transaction_ids == ["t1", "t2"]

    def test_resolve_anomaly(self, db):
        anomaly = Anomaly(type="SPIKE", severity="high")
        db.save_anomaly(anomaly)

        assert db.resolve_anomaly(anomaly.id) is True
        assert len(db.get_unresolved_anomalies()) == 0

    def test_resolve_nonexistent(self, db):
        assert db.resolve_anomaly("fake-id") is False


# =====================================================================
# Analytics tests
# =====================================================================

class TestAnalytics:
    """Test spending analytics queries."""

    def test_spending_by_category(self, db):
        db.save_transaction(_make_transaction(category="Dining", amount=25.00))
        db.save_transaction(_make_transaction(category="Dining", amount=15.00))
        db.save_transaction(_make_transaction(category="Shopping", amount=100.00))

        by_cat = db.get_spending_by_category(days=1)
        assert by_cat["Shopping"] == 100.00
        assert by_cat["Dining"] == 40.00

    def test_spending_trend(self, db):
        # Add transactions in current week
        db.save_transaction(_make_transaction(amount=50.00))
        db.save_transaction(_make_transaction(amount=30.00))

        trend = db.get_spending_trend(weeks=4)
        assert len(trend) == 4
        # Most recent week should have our transactions
        assert trend[0]["total_spent"] == 80.00
        assert trend[0]["transaction_count"] == 2

    def test_merchant_history(self, db):
        db.save_transaction(_make_transaction(merchant="Starbucks", amount=5.45))
        db.save_transaction(_make_transaction(merchant="Starbucks", amount=6.20))
        db.save_transaction(_make_transaction(merchant="Starbucks", amount=4.80))

        history = db.get_merchant_history("Starbucks")
        assert history["count"] == 3
        assert history["total"] == pytest.approx(16.45, abs=0.01)
        assert history["average"] == pytest.approx(5.48, abs=0.01)

    def test_get_stats(self, db):
        db.save_transaction(_make_transaction())
        db.save_subscription(_make_subscription())
        db.save_anomaly(Anomaly(type="TEST"))

        stats = db.get_stats()
        assert stats["transactions"] == 1
        assert stats["subscriptions"] == 1
        assert stats["anomalies"] == 1


# =====================================================================
# No PII in database test
# =====================================================================

class TestNoPIIInDatabase:
    """Verify that raw email content and PII are never stored."""

    def test_no_email_body_stored(self, db):
        """Scan all text columns — no raw email content should exist."""
        # Save some transactions
        db.save_transaction(_make_transaction(merchant="Chase Bank"))
        db.save_transaction(_make_transaction(merchant="PayPal"))

        # Scan all text in the database
        pii_patterns = [
            "4532-8821-0093-4892",  # credit card
            "478-39-6781",          # SSN
            "michael.thompson@gmail.com",  # email
            "(415) 555-8291",       # phone
            "1234 Oak Street",      # address
        ]

        for table in ("transactions", "subscriptions", "anomalies", "audit_log"):
            rows = db._conn.execute(f"SELECT * FROM {table}").fetchall()
            for row in rows:
                row_str = str(row)
                for pattern in pii_patterns:
                    assert pattern not in row_str, (
                        f"PII '{pattern}' found in {table}: {row_str}"
                    )


# =====================================================================
# Fallback to unencrypted SQLite test
# =====================================================================

class TestFallback:
    """Test graceful fallback when sqlcipher is unavailable."""

    def test_fallback_to_sqlite(self, tmp_path):
        """With empty encryption key, should use plain sqlite3."""
        path = str(tmp_path / "fallback.db")
        db = EncryptedDatabase(db_path=path, encryption_key="")
        assert db.is_encrypted is False

        # Should still work for all operations
        tx = _make_transaction()
        db.save_transaction(tx)
        retrieved = db.get_transaction_by_id(tx.id)
        assert retrieved is not None
        db.close()


# =====================================================================
# Audit Logger tests
# =====================================================================

class TestAuditLogger:
    """Test audit logging functionality."""

    def test_log_creates_entry(self, auditor):
        entry = auditor.log(action="test_action", details="test details")
        assert entry.action == "test_action"
        assert entry.details == "test details"
        assert entry.entry_hash != ""

    def test_log_written_to_db(self, auditor, db):
        auditor.log(action="db_test", details="check db")
        entries = db.get_audit_entries(count=10)
        assert len(entries) >= 1
        assert entries[0].action == "db_test"

    def test_log_written_to_jsonl(self, auditor, tmp_path):
        log_file = tmp_path / "audit_test.jsonl"
        auditor.log(action="file_test", details="check file")

        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) >= 1
        parsed = json.loads(lines[-1])
        assert parsed["action"] == "file_test"

    def test_critical_events(self, auditor, capsys):
        """CRITICAL events should print to stderr."""
        auditor.log(action="critical_test", details="something bad", level="CRITICAL")
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.err or "critical_test" in captured.err

    def test_convenience_methods(self, auditor):
        auditor.log_scan_start(days=30, max_results=50)
        auditor.log_email_processed("msg-001", redaction_count=5, had_injection=False)
        auditor.log_categorization("Starbucks", 5.45, "Dining")
        auditor.log_anomaly_detected("DUPLICATE", "medium", "Possible dup")
        auditor.log_response_sent(100, pii_found_in_output=False)
        auditor.log_security_event("prompt_injection", "Detected in msg-010")

        entries = auditor.get_recent_entries(count=10)
        assert len(entries) == 6

    def test_injection_logged_as_critical(self, auditor):
        auditor.log_email_processed("msg-010", redaction_count=3, had_injection=True)
        critical = auditor.get_recent_entries(count=10, level="CRITICAL")
        assert len(critical) >= 1
        assert "INJECTION" in critical[0].details.upper()

    def test_pii_in_output_logged_critical(self, auditor):
        auditor.log_response_sent(200, pii_found_in_output=True)
        critical = auditor.get_recent_entries(count=10, level="CRITICAL")
        assert len(critical) >= 1
        assert "PII" in critical[0].details.upper()


# =====================================================================
# Hash chain integrity tests
# =====================================================================

class TestHashChainIntegrity:
    """Test the tamper-evident hash chain."""

    def test_chain_intact_after_writes(self, auditor):
        """Write 10 entries, verify chain is intact."""
        for i in range(10):
            auditor.log(action=f"entry_{i}", details=f"Detail {i}")

        assert auditor.verify_integrity() is True

    def test_chain_genesis(self, auditor):
        """Empty audit log should pass integrity check."""
        # Fresh auditor with no entries
        assert auditor.verify_integrity() is True

    def test_tamper_detection(self, auditor, db):
        """Write 10 entries, tamper with one, verify chain breaks."""
        for i in range(10):
            auditor.log(action=f"entry_{i}", details=f"Detail {i}")

        # Verify intact first
        assert auditor.verify_integrity() is True

        # Now tamper: modify the details of a middle entry
        entries = db.get_audit_entries(count=100)
        target = entries[5]  # pick one in the middle
        db._conn.execute(
            "UPDATE audit_log SET details = 'TAMPERED' WHERE id = ?",
            (target.id,),
        )
        db._conn.commit()

        # Chain should now be broken
        assert auditor.verify_integrity() is False

    def test_hash_chain_links(self, auditor, db):
        """Verify each entry's previous_hash matches the prior entry's hash."""
        for i in range(5):
            auditor.log(action=f"chain_{i}", details=f"Link {i}")

        entries = db.get_audit_entries(count=100)
        # Entries come newest-first; reverse for chain order
        entries = list(reversed(entries))

        assert entries[0].previous_hash == "GENESIS"
        for i in range(1, len(entries)):
            assert entries[i].previous_hash == entries[i - 1].entry_hash, (
                f"Chain broken at entry {i}"
            )


# =====================================================================
# Audit report tests
# =====================================================================

class TestAuditReport:
    """Test audit report generation."""

    def test_generate_report(self, auditor):
        auditor.log_scan_start(30, 50)
        auditor.log_email_processed("e1", 5, False)
        auditor.log_email_processed("e2", 3, True)
        auditor.log_categorization("Amazon", 29.99, "Shopping")
        auditor.log_anomaly_detected("SECURITY", "critical", "Injection found")

        report = auditor.generate_audit_report(days=1)
        assert report["total_actions"] == 5
        assert report["emails_processed"] == 2
        assert report["total_redactions"] == 8
        assert report["anomalies_found"] == 1
        assert report["security_events"] >= 2  # injection email + anomaly
        assert report["chain_integrity"] is True

    def test_get_security_events(self, auditor):
        auditor.log(action="normal", level="INFO")
        auditor.log_security_event("test_threat", "Something suspicious")
        auditor.log(action="another_normal", level="INFO")

        events = auditor.get_security_events(days=1)
        assert len(events) == 1
        assert "test_threat" in events[0].action


# =====================================================================
# No PII in audit entries test
# =====================================================================

class TestNoPIIInAudit:
    """Verify that audit entries themselves contain no PII."""

    def test_audit_entries_clean(self, auditor):
        """Log various events and scan for PII patterns."""
        auditor.log_scan_start(30, 50)
        auditor.log_email_processed("msg-001", 5, False)
        auditor.log_categorization("Chase Bank", 127.43, "Bills/Utilities")
        auditor.log_anomaly_detected("SPIKE", "high", "Unusual amount at Chase")
        auditor.log_response_sent(500, False)

        entries = auditor.get_recent_entries(count=100)

        pii_patterns = [
            "4532-8821-0093-4892",
            "478-39-6781",
            "michael.thompson@gmail.com",
            "(415) 555-8291",
            "1234 Oak Street",
        ]

        for entry in entries:
            entry_str = json.dumps(entry.to_dict())
            for pattern in pii_patterns:
                assert pattern not in entry_str, (
                    f"PII '{pattern}' found in audit entry: {entry_str}"
                )

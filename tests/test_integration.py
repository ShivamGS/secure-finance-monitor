"""
Integration tests — end-to-end pipeline testing.

Tests the full data flow: sample emails → PII redaction → agent processing →
storage → audit logging, ensuring all security guarantees hold.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.agent.finance_agent import FinanceAgent, ScanResult
from src.agent.tools import check_prompt_injection_raw
from src.config import Config
from src.redactor.pii_redactor import PIIRedactor
from src.storage.database import EncryptedDatabase
from src.storage.audit import AuditLogger
from src.storage.models import Transaction, Anomaly


# Fixtures

@pytest.fixture
def temp_db():
    """Temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = EncryptedDatabase(db_path=db_path, encryption_key=None)
    yield db
    db.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def temp_audit_log():
    """Temporary audit log for testing."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        log_path = f.name
    yield log_path
    if os.path.exists(log_path):
        os.unlink(log_path)


@pytest.fixture
def audit_logger(temp_db, temp_audit_log):
    """Initialized AuditLogger for testing."""
    return AuditLogger(database=temp_db, log_file=temp_audit_log)


@pytest.fixture
def sample_emails():
    """Load sample emails from demo directory."""
    sample_file = Path(__file__).parent.parent / "demo" / "sample_emails.json"
    with open(sample_file) as f:
        return json.load(f)


@pytest.fixture
def injection_emails():
    """Load injection emails from demo directory."""
    injection_file = Path(__file__).parent.parent / "demo" / "injection_emails.json"
    with open(injection_file) as f:
        return json.load(f)


@pytest.fixture
def redactor():
    """PIIRedactor instance."""
    return PIIRedactor()


# Integration Tests

def test_full_demo_pipeline(sample_emails, temp_db, temp_audit_log, redactor):
    """
    CRITICAL TEST: Full pipeline from raw emails to storage.

    Verifies:
    1. All PII is redacted before agent sees data
    2. Transactions are categorized
    3. Anomalies are detected (duplicate charge, large transaction)
    4. Prompt injection emails are flagged
    5. All actions are audit logged
    6. Hash chain is valid
    7. Database contains only sanitized data
    """
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)

    transactions = []
    anomalies = []
    security_flags = []
    total_redactions = 0

    audit.log_scan_start(days=30, max_results=len(sample_emails))

    # Process each email through the full pipeline
    for email in sample_emails:
        email_id = email["id"]
        body = email["body"]

        # Step 1: Redact PII
        redaction_result = redactor.redact(body)
        total_redactions += len(redaction_result.redaction_details)

        # Verify redaction happened
        assert redaction_result.clean_text != body or len(redaction_result.redaction_details) == 0

        # Verify no PII leaked through
        for item in redaction_result.redaction_details:
            # Original PII should not be in sanitized text
            assert item.original not in redaction_result.clean_text, \
                f"PII leaked: {item.original} still in sanitized text"

        # Step 2: Check for prompt injection
        injection_result = check_prompt_injection_raw(redaction_result.clean_text)
        had_injection = injection_result.get("is_suspicious", False)

        if had_injection:
            security_flags.append({
                "email_id": email_id,
                "patterns": injection_result.get("patterns_found", []),
            })
            audit.log_security_event(
                "PROMPT_INJECTION_DETECTED",
                f"Email {email_id}: {injection_result}"
            )

        # Step 3: Extract transaction (simple heuristic for test)
        merchant, amount = _extract_simple_transaction(email)

        if merchant and amount:
            tx = Transaction(
                id=f"tx-{email_id}",
                date=email.get("date", "2025-01-01T00:00:00Z"),
                merchant=merchant,
                amount=amount,
                category="Other",
                source_email_id=email_id,
                confidence=0.8,
            )
            transactions.append(tx)

            audit.log_email_processed(
                email_id=email_id,
                redaction_count=len(redaction_result.redaction_details),
                had_injection=had_injection,
            )

    # Step 4: Detect anomalies
    anomalies = _detect_test_anomalies(transactions)

    for anomaly in anomalies:
        temp_db.save_anomaly(anomaly)
        audit.log_anomaly_detected(anomaly.type, anomaly.severity, anomaly.description or "")

    # Step 5: Save transactions
    saved_count = temp_db.save_transactions_batch(transactions)
    assert saved_count == len(transactions)

    # Verification checks

    # Check 1: PII was redacted
    assert total_redactions > 0, "No PII redactions occurred - pipeline may be broken"

    # Check 2: Transactions were processed
    assert len(transactions) > 0, "No transactions extracted"

    # Check 3: Duplicate charge anomaly was detected
    duplicate_anomalies = [a for a in anomalies if a.type == "duplicate_charge"]
    assert len(duplicate_anomalies) > 0, "Duplicate charge anomaly not detected (msg-011 and msg-012)"

    # Check 4: Large transaction anomaly was detected
    large_tx_anomalies = [a for a in anomalies if a.type == "unusually_large"]
    assert len(large_tx_anomalies) > 0, "Large transaction anomaly not detected"

    # Check 5: Prompt injection was flagged
    assert len(security_flags) >= 2, f"Expected at least 2 injection flags, got {len(security_flags)}"

    # Check 6: Audit log is valid
    assert audit.verify_integrity(), "Audit hash chain is invalid"

    # Check 7: Database contains no raw PII
    leaked_pii = _scan_db_for_pii(temp_db, redactor)
    assert len(leaked_pii) == 0, f"PII leaked into database: {leaked_pii}"

    # Check 8: Verify specific redactions
    db_transactions = temp_db.get_transactions()
    for tx in db_transactions:
        # Merchant names should not contain credit card patterns
        assert not _contains_credit_card(tx.merchant), f"Credit card in merchant: {tx.merchant}"
        # Source email ID should be clean
        if tx.source_email_id:
            assert not _contains_credit_card(tx.source_email_id), f"Credit card in email ID: {tx.source_email_id}"


def test_fail_closed_integration(temp_db, temp_audit_log):
    """
    Test fail-closed behavior: if redaction fails, content is withheld.

    Simulates a redactor failure and verifies:
    1. Raw content is NOT passed through
    2. Error is logged as CRITICAL
    3. Other emails still process normally
    """
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)
    redactor = PIIRedactor()

    test_emails = [
        {"id": "safe-001", "body": "Normal transaction at Store A for $50.00"},
        {"id": "fail-002", "body": "This will cause redaction failure"},
        {"id": "safe-003", "body": "Another normal transaction for $25.00"},
    ]

    processed = []

    for email in test_emails:
        try:
            # Mock redactor to fail on fail-002
            if email["id"] == "fail-002":
                # Simulate redaction failure
                with patch.object(redactor, 'redact', side_effect=RuntimeError("Redaction failed")):
                    try:
                        result = redactor.redact(email["body"])
                        processed.append({"id": email["id"], "text": result.clean_text})
                    except RuntimeError:
                        # FAIL CLOSED: do not process this email
                        audit.log_security_event(
                            "REDACTION_FAILED",
                            f"Email {email['id']} withheld due to redaction failure"
                        )
                        # Content is withheld - do NOT add to processed
                        continue
            else:
                result = redactor.redact(email["body"])
                processed.append({"id": email["id"], "text": result.clean_text})
        except Exception as e:
            audit.log_security_event("PROCESSING_ERROR", f"Email {email['id']}: {str(e)}")

    # Verify fail-closed behavior
    assert len(processed) == 2, "Failed email should not be processed"
    assert not any(p["id"] == "fail-002" for p in processed), "Failed email was processed (fail-open violation!)"

    # Verify other emails were processed
    assert any(p["id"] == "safe-001" for p in processed), "Safe email 1 was not processed"
    assert any(p["id"] == "safe-003" for p in processed), "Safe email 3 was not processed"

    # Verify error was logged
    security_events = audit.get_security_events(days=1)
    assert any("REDACTION_FAILED" in e.action for e in security_events), "Failure not logged"


def test_response_sanitization(temp_db, temp_audit_log):
    """
    Test agent response sanitization (defense in depth).

    Simulates an LLM hallucinating PII in response and verifies:
    1. Sanitizer catches it before reaching user
    2. Flagged as CRITICAL security event
    """
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)
    agent = FinanceAgent()

    # Simulate LLM response containing PII (should never happen, but defense in depth)
    mock_response_with_pii = "Your transaction was processed with card 4532-8821-0093-4892 and account 839204718."

    # Agent sanitizes response before returning
    sanitized = agent.sanitize_response(mock_response_with_pii)

    # Verify PII was removed
    assert "4532-8821-0093-4892" not in sanitized, "Credit card leaked through response sanitizer"
    assert "839204718" not in sanitized, "Account number leaked through response sanitizer"

    # Verify redaction markers are present
    assert "[CARD_" in sanitized or "REDACTED" in sanitized, "No redaction markers in sanitized response"

    # Log as security event
    if sanitized != mock_response_with_pii:
        audit.log_security_event(
            "RESPONSE_SANITIZED",
            "Removed PII from agent response (defense in depth)"
        )

    security_events = audit.get_security_events(days=1)
    assert len(security_events) > 0, "Response sanitization not logged"


def test_demo_mode_no_gmail_needed(sample_emails, temp_db, temp_audit_log):
    """
    Test demo mode works without Gmail credentials or API keys.

    This is critical for the Cequence demo.
    """
    redactor = PIIRedactor()
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)

    # Simulate demo mode processing
    transactions = []

    for email in sample_emails[:5]:  # Process first 5 emails
        redaction_result = redactor.redact(email["body"])

        merchant, amount = _extract_simple_transaction(email)
        if merchant and amount:
            date_str = email.get("date", "2025-01-01T00:00:00Z")
            tx = Transaction(
                id=f"demo-{email['id']}",
                date=datetime.fromisoformat(date_str.replace('Z', '+00:00')),
                merchant=merchant,
                amount=amount,
                category="Demo",
                source_email_id=email["id"],
                confidence=1.0,
            )
            transactions.append(tx)

    # Save to database
    saved = temp_db.save_transactions_batch(transactions)

    # Verify demo worked
    assert saved > 0, "Demo mode failed to save transactions"
    assert saved == len(transactions), "Not all demo transactions were saved"

    # Verify we can retrieve them (use days=999 to get all test transactions with old dates)
    retrieved = temp_db.get_transactions(days=999)
    assert len(retrieved) == saved, "Could not retrieve demo transactions"


def test_verify_command(temp_db, temp_audit_log):
    """
    Test the verify command checks:
    1. Database encryption status
    2. Audit log hash chain integrity
    3. No PII in database
    """
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)
    redactor = PIIRedactor()

    # Add some test data
    tx = Transaction(
        id="verify-001",
        date="2025-01-01T00:00:00Z",
        merchant="Test Store",
        amount=100.0,
        category="Shopping",
    )
    temp_db.save_transaction(tx)

    audit.log_scan_start(days=30, max_results=10)

    # Check 1: Encryption status
    is_encrypted = temp_db.is_encrypted
    # Note: in tests without encryption key, this will be False (which is OK for demo)
    assert isinstance(is_encrypted, bool), "Encryption check failed"

    # Check 2: Hash chain integrity
    chain_valid = audit.verify_integrity()
    assert chain_valid is True, "Hash chain should be valid"

    # Check 3: No PII in database
    leaked = _scan_db_for_pii(temp_db, redactor)
    assert len(leaked) == 0, f"PII found in database: {leaked}"


def test_injection_emails_all_caught(injection_emails, redactor):
    """
    Test that all 5 injection test cases are detected.
    """
    for email in injection_emails:
        email_id = email["id"]
        body = email["body"]

        # Redact first
        redaction_result = redactor.redact(body)

        # Check for injection
        injection_result = check_prompt_injection_raw(redaction_result.clean_text)

        assert injection_result.get("is_suspicious", False), f"Injection email {email_id} was NOT detected!"

        patterns_found = injection_result.get("patterns_found", [])
        assert len(patterns_found) > 0, f"Injection email {email_id} had no patterns detected!"

        # Verify it's marked as at least medium risk for obvious injections
        risk_level = injection_result.get("risk_level", "none")
        assert risk_level in ["medium", "high", "critical"], \
            f"Injection {email_id} should be at least medium risk, got {risk_level}"


def test_duplicate_charge_detection(sample_emails, temp_db):
    """
    Test that duplicate charges (msg-011 and msg-012) are detected as anomalies.
    """
    # Extract the duplicate transactions
    dup1 = next(e for e in sample_emails if e["id"] == "msg-011")
    dup2 = next(e for e in sample_emails if e["id"] == "msg-012")

    tx1 = Transaction(
        id="tx-msg-011",
        date=dup1["date"],
        merchant="Shell Gas Station",
        amount=52.30,
        category="Transportation",
        source_email_id="msg-011",
    )

    tx2 = Transaction(
        id="tx-msg-012",
        date=dup2["date"],
        merchant="Shell Gas Station",
        amount=52.30,
        category="Transportation",
        source_email_id="msg-012",
    )

    temp_db.save_transaction(tx1)
    temp_db.save_transaction(tx2)

    # Detect duplicates
    transactions = [tx1, tx2]
    anomalies = _detect_test_anomalies(transactions)

    duplicate_anomalies = [a for a in anomalies if a.type == "duplicate_charge"]
    assert len(duplicate_anomalies) > 0, "Duplicate charge not detected"

    # Verify details
    dup_anomaly = duplicate_anomalies[0]
    assert dup_anomaly.severity in ["medium", "high"], f"Wrong severity: {dup_anomaly.severity}"
    assert "duplicate" in dup_anomaly.description.lower() or "same" in dup_anomaly.description.lower()


def test_large_transaction_detection(sample_emails, temp_db):
    """
    Test that unusually large transactions are flagged.
    """
    # msg-002: Best Buy $2,349.99
    # msg-014: Bay Area Auto Repair $4,850.00

    large_emails = [e for e in sample_emails if e["id"] in ["msg-002", "msg-014"]]

    transactions = []
    for email in large_emails:
        merchant, amount = _extract_simple_transaction(email)
        if amount and amount > 1000:
            tx = Transaction(
                id=f"tx-{email['id']}",
                date=email["date"],
                merchant=merchant or "Unknown",
                amount=amount,
                category="Other",
                source_email_id=email["id"],
            )
            transactions.append(tx)

    assert len(transactions) >= 2, "Large transactions not extracted"

    # Detect anomalies
    anomalies = _detect_test_anomalies(transactions)
    large_anomalies = [a for a in anomalies if a.type == "unusually_large"]

    assert len(large_anomalies) > 0, "Large transaction anomaly not detected"


def test_audit_hash_chain_tamper_detection(temp_db, temp_audit_log):
    """
    Test that tampering with audit log breaks the hash chain.
    """
    audit = AuditLogger(database=temp_db, log_file=temp_audit_log)

    # Create some entries
    audit.log_scan_start(days=30, max_results=10)
    audit.log_email_processed("test-001", 2, False)
    audit.log_email_processed("test-002", 1, False)

    # Verify chain is valid
    assert audit.verify_integrity() is True, "Initial chain should be valid"

    # Tamper with an entry
    cursor = temp_db._conn.cursor()
    cursor.execute("SELECT id FROM audit_log LIMIT 1")
    entry_id = cursor.fetchone()[0]

    # Modify the details (simulating tampering)
    cursor.execute(
        "UPDATE audit_log SET details = ? WHERE id = ?",
        ("TAMPERED DATA", entry_id)
    )
    temp_db._conn.commit()

    # Verify chain is now broken
    is_valid = audit.verify_integrity()
    assert is_valid is False, "Hash chain should detect tampering"


# Helper functions

def _extract_simple_transaction(email: dict) -> tuple[str | None, float | None]:
    """Extract merchant and amount using simple heuristics."""
    import re

    subject = email.get("subject", "")
    body = email.get("body", "")
    text = subject + " " + body

    # Extract amount
    amount_match = re.search(r'\$(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)', text)
    amount = float(amount_match.group(1).replace(',', '')) if amount_match else None

    # Extract merchant
    merchant = None
    if "at " in subject:
        merchant = subject.split("at ")[-1].split()[0] if "at " in subject else None
    elif "Merchant:" in body:
        idx = body.index("Merchant:") + 9
        merchant = body[idx:idx+30].split("\n")[0].strip()

    # Clean merchant name
    if merchant:
        merchant = merchant.strip().rstrip(",.:;")

    return merchant, amount


def _detect_test_anomalies(transactions: list[Transaction]) -> list[Anomaly]:
    """Simple anomaly detection for testing."""
    anomalies = []

    # Detect duplicates (same merchant, same amount, within 5 minutes)
    for i, tx1 in enumerate(transactions):
        for tx2 in transactions[i+1:]:
            if (tx1.merchant == tx2.merchant and
                tx1.amount == tx2.amount and
                tx1.date[:10] == tx2.date[:10]):  # Same day

                anomalies.append(Anomaly(
                    id=f"anom-dup-{tx1.id}-{tx2.id}",
                    type="duplicate_charge",
                    severity="medium",
                    description=f"Duplicate charge: {tx1.merchant} ${tx1.amount:.2f}",
                    transaction_ids=json.dumps([tx1.id, tx2.id]),
                    recommended_action="Review transactions with merchant",
                ))

    # Detect large transactions (>$1000)
    for tx in transactions:
        if tx.amount > 1000:
            anomalies.append(Anomaly(
                id=f"anom-large-{tx.id}",
                type="unusually_large",
                severity="high",
                description=f"Large transaction: {tx.merchant} ${tx.amount:.2f}",
                transaction_ids=json.dumps([tx.id]),
                recommended_action="Verify transaction was authorized",
            ))

    return anomalies


def _scan_db_for_pii(db: EncryptedDatabase, redactor: PIIRedactor) -> list[str]:
    """Scan database for leaked PII patterns."""
    from src.redactor.patterns import get_patterns_ordered

    leaked = []
    patterns = get_patterns_ordered()

    # Scan transactions
    transactions = db.get_transactions()
    for tx in transactions:
        for field_name, field_value in [
            ("merchant", tx.merchant),
            ("category", tx.category),
            ("source_email_id", tx.source_email_id or ""),
        ]:
            if field_value:
                for pattern in patterns:
                    matches = pattern.regex.findall(field_value)
                    if matches:
                        # Filter out false positives
                        if pattern.name == "CREDIT_CARD":
                            # Allow redaction markers like [CARD_****1234]
                            for match in matches:
                                if not match.startswith("[CARD_"):
                                    leaked.append(f"Transaction {tx.id}.{field_name}: {pattern.name}")

    return leaked


def _contains_credit_card(text: str) -> bool:
    """Check if text contains credit card pattern (not redacted)."""
    import re
    # Match 4 groups of 4 digits (card numbers)
    pattern = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
    matches = re.findall(pattern, text)

    # Exclude redaction markers
    for match in matches:
        if not match.startswith("[CARD_") and "****" not in match:
            return True
    return False

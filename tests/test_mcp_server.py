"""
Tests for the MCP server tools.

Uses mock Gmail API responses built from demo/sample_emails.json.
Verifies that:
- All returned content is PII-redacted
- If redaction fails, tools return errors (FAIL CLOSED)
- Financial summary correctly extracts amounts and merchants
- Query builder generates correct Gmail query strings
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.mcp_server.server import (
    fetch_financial_emails,
    get_email_detail,
    get_financial_summary,
    _redact_email_body,
    _extract_merchant,
    _extract_amounts,
    _infer_category,
)
from src.mcp_server.gmail_client import GmailClient, DEFAULT_FINANCIAL_SENDERS


@pytest.fixture(scope="module")
def sample_emails() -> list[dict]:
    path = os.path.join(os.path.dirname(__file__), "..", "demo", "sample_emails.json")
    with open(path) as f:
        return json.load(f)


def _make_mock_client(sample_emails: list[dict]) -> MagicMock:
    """Create a mock GmailClient that returns sample emails."""
    mock = MagicMock(spec=GmailClient)

    # search_emails returns metadata
    mock.search_emails.return_value = [
        {
            "id": e["id"],
            "sender": e["sender"],
            "sender_email": e["sender"],
            "subject": e["subject"],
            "date": e["date"],
            "snippet": e["body"][:100],
        }
        for e in sample_emails
    ]

    # get_email_body returns full email
    def mock_get_body(email_id: str) -> dict:
        for e in sample_emails:
            if e["id"] == email_id:
                return {
                    "id": e["id"],
                    "sender": e["sender"],
                    "sender_email": e["sender"],
                    "subject": e["subject"],
                    "date": e["date"],
                    "body": e["body"],
                }
        raise ValueError(f"Email {email_id} not found")

    mock.get_email_body.side_effect = mock_get_body
    mock.build_financial_query.return_value = "(from:*@chase.com) newer_than:30d"

    return mock


# =====================================================================
# Redaction pipeline tests
# =====================================================================

class TestRedactEmailBody:
    """Test the _redact_email_body helper."""

    def test_redacts_pii(self, sample_emails: list[dict]):
        result = _redact_email_body(sample_emails[0]["body"])
        assert "redacted_body" in result
        assert "redaction_report" in result
        # Card number should be redacted
        assert "4532-8821-0093-4892" not in result["redacted_body"]
        # Dollar amount should be preserved
        assert "$127.43" in result["redacted_body"]

    def test_redaction_report_has_count(self, sample_emails: list[dict]):
        result = _redact_email_body(sample_emails[0]["body"])
        assert result["redaction_report"]["redaction_count"] > 0
        assert isinstance(result["redaction_report"]["is_valid"], bool)

    def test_all_emails_redacted(self, sample_emails: list[dict]):
        """Every sample email should be redactable."""
        for email in sample_emails:
            result = _redact_email_body(email["body"])
            assert "redacted_body" in result
            assert len(result["redacted_body"]) > 0


# =====================================================================
# FAIL CLOSED tests
# =====================================================================

class TestFailClosed:
    """If redaction fails, tools must return errors — never raw content."""

    def test_redact_body_raises_on_pipeline_failure(self):
        """If the redactor returns the error sentinel, _redact_email_body should raise."""
        with patch("src.mcp_server.server._redactor") as mock_redactor:
            mock_result = MagicMock()
            mock_result.clean_text = "[REDACTION_ERROR: content withheld for safety]"
            mock_redactor.redact.return_value = mock_result

            with pytest.raises(RuntimeError, match="content withheld for safety"):
                _redact_email_body("Some email with SSN 123-45-6789")

    def test_fetch_emails_fail_closed(self, sample_emails: list[dict]):
        """If redaction fails for an email, the response says content withheld."""
        mock_client = _make_mock_client(sample_emails[:1])

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            with patch("src.mcp_server.server._redactor") as mock_redactor:
                mock_redactor.redact.side_effect = RuntimeError("Redaction failed")
                result = fetch_financial_emails(days=30, max_results=10)

        assert len(result["emails"]) == 1
        assert "withheld" in result["emails"][0]["redacted_body"].lower()

    def test_get_email_detail_fail_closed(self, sample_emails: list[dict]):
        """If redaction fails for a single email, return error — not raw content."""
        mock_client = _make_mock_client(sample_emails)

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            with patch("src.mcp_server.server._redact_email_body") as mock_redact:
                mock_redact.side_effect = RuntimeError("Redaction failed")
                result = get_email_detail("msg-001")

        assert "error" in result
        assert "withheld" in result["error"].lower()
        # CRITICAL: raw body must NOT be present
        assert "body" not in result or "4532" not in str(result.get("body", ""))


# =====================================================================
# fetch_financial_emails tests
# =====================================================================

class TestFetchFinancialEmails:
    """Test the fetch_financial_emails MCP tool."""

    def test_returns_redacted_emails(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails[:3])  # Chase emails

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = fetch_financial_emails(days=30, max_results=10)

        assert result["total_emails"] == 3
        assert result["total_redactions"] > 0

        for email in result["emails"]:
            assert "redacted_body" in email
            assert "redaction_report" in email
            # No raw credit card numbers
            assert "4532-8821-0093-4892" not in email["redacted_body"]
            # No raw account numbers
            assert "839204718" not in email["redacted_body"]

    def test_preserves_financial_data(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails[:1])

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = fetch_financial_emails(days=30, max_results=10)

        email = result["emails"][0]
        assert "$127.43" in email["redacted_body"]
        assert "Whole Foods Market" in email["redacted_body"]

    def test_handles_gmail_api_error(self):
        mock_client = MagicMock()
        mock_client.build_financial_query.side_effect = Exception("API error")

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = fetch_financial_emails(days=30, max_results=10)

        assert "error" in result
        assert result["emails"] == []

    def test_audit_summary_present(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails[:2])

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = fetch_financial_emails(days=30, max_results=10)

        assert "audit_summary" in result
        assert "emails fetched" in result["audit_summary"]
        assert "PII items redacted" in result["audit_summary"]


# =====================================================================
# get_email_detail tests
# =====================================================================

class TestGetEmailDetail:
    """Test the get_email_detail MCP tool."""

    def test_returns_redacted_detail(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails)

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_email_detail("msg-001")

        assert result["id"] == "msg-001"
        assert "redacted_body" in result
        assert "4532-8821-0093-4892" not in result["redacted_body"]
        assert "$127.43" in result["redacted_body"]

    def test_handles_missing_email(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails)

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_email_detail("nonexistent-id")

        assert "error" in result

    def test_injection_email_safe(self, sample_emails: list[dict]):
        """The prompt injection email (msg-010) should be fully redacted."""
        mock_client = _make_mock_client(sample_emails)

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_email_detail("msg-010")

        assert "redacted_body" in result
        # PII within injection email is redacted
        assert "4532-8821-0093-4892" not in result["redacted_body"]
        assert "478-39-6781" not in result["redacted_body"]
        assert "michael.thompson@gmail.com" not in result["redacted_body"]


# =====================================================================
# get_financial_summary tests
# =====================================================================

class TestGetFinancialSummary:
    """Test the get_financial_summary MCP tool."""

    def test_extracts_transactions(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails[:3])

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_financial_summary(days=30)

        assert result["total_transactions"] == 3
        assert len(result["transactions"]) == 3

        for txn in result["transactions"]:
            assert "date" in txn
            assert "merchant" in txn
            assert "amounts" in txn
            assert "category_hint" in txn

    def test_amounts_extracted_correctly(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails[:1])

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_financial_summary(days=30)

        txn = result["transactions"][0]
        assert "$127.43" in txn["amounts"]

    def test_no_raw_pii_in_transactions(self, sample_emails: list[dict]):
        mock_client = _make_mock_client(sample_emails)

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_financial_summary(days=30)

        result_str = json.dumps(result)
        # No raw credit cards
        assert "4532-8821-0093-4892" not in result_str
        # No raw SSNs
        assert "478-39-6781" not in result_str
        # No raw emails
        assert "michael.thompson@gmail.com" not in result_str

    def test_handles_gmail_error(self):
        mock_client = MagicMock()
        mock_client.build_financial_query.side_effect = Exception("API error")

        with patch("src.mcp_server.server._get_gmail_client", return_value=mock_client):
            result = get_financial_summary(days=7)

        assert "error" in result
        assert result["transactions"] == []


# =====================================================================
# Helper function tests
# =====================================================================

class TestHelpers:
    """Test utility functions used by the MCP tools."""

    def test_extract_amounts(self):
        assert _extract_amounts("Paid $127.43 and $52.30") == ["$127.43", "$52.30"]
        assert _extract_amounts("Total: $2,349.99") == ["$2,349.99"]
        assert _extract_amounts("No amounts here") == []
        assert _extract_amounts("Balance: $0.00") == ["$0.00"]

    def test_extract_merchant_from_name(self):
        assert _extract_merchant("Chase Bank", "alerts@chase.com") == "Chase Bank"
        assert _extract_merchant("Netflix", "info@members.netflix.com") == "Netflix"

    def test_extract_merchant_from_email(self):
        assert _extract_merchant("", "alerts@chase.com") == "Chase"
        assert _extract_merchant("service@paypal.com", "service@paypal.com") == "Paypal"

    def test_infer_category(self):
        assert _infer_category("Your Netflix subscription renewed", "Netflix") == "subscription"
        assert _infer_category("Order shipped", "Amazon") == "shopping"
        assert _infer_category("You paid David Lee", "Venmo") == "transfer"
        assert _infer_category("Transaction at Shell", "Shell") == "gas"
        assert _infer_category("Random subject", "Unknown Corp") == "other"


# =====================================================================
# Query builder tests
# =====================================================================

class TestQueryBuilder:
    """Test the Gmail query string builder."""

    def test_default_query(self):
        # Instantiate directly to test the method (no OAuth needed)
        query = GmailClient.build_financial_query(None, days=30)
        assert "newer_than:30d" in query
        assert "from:*@chase.com" in query
        assert "from:*@paypal.com" in query
        assert "from:*@netflix.com" in query

    def test_custom_senders(self):
        query = GmailClient.build_financial_query(
            None, days=7, custom_senders=["*@mybank.com"]
        )
        assert "newer_than:7d" in query
        assert "from:*@mybank.com" in query
        # Default senders still present
        assert "from:*@chase.com" in query

    def test_query_uses_or(self):
        query = GmailClient.build_financial_query(None, days=30)
        assert " OR " in query

    def test_default_senders_list(self):
        """Verify all expected default senders are in the list."""
        expected = ["chase.com", "paypal.com", "venmo.com", "amazon.com", "netflix.com"]
        for domain in expected:
            assert any(domain in s for s in DEFAULT_FINANCIAL_SENDERS)

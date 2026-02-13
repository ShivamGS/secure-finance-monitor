"""
FastMCP server exposing Gmail financial email tools.

SECURITY INVARIANT: Every email body passes through PIIRedactor.redact()
before being returned. Raw email content is NEVER returned, stored, or cached.
If redaction fails, the tool returns an error — FAIL CLOSED.
"""

import os
import re
import logging
from datetime import datetime

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from ..redactor.pii_redactor import PIIRedactor, RedactionStats

load_dotenv()

logger = logging.getLogger(__name__)

mcp = FastMCP("secure-finance-monitor")

# Singleton redactor — initialized once, reused across requests
_redactor = PIIRedactor()

# Dollar amount extraction regex (used by get_financial_summary)
_DOLLAR_PATTERN = re.compile(r"\$[\d,]+\.?\d{0,2}")


def _get_gmail_client():
    """Lazy-load GmailClient to avoid import-time OAuth flow."""
    from .gmail_client import GmailClient
    return GmailClient()


def _redact_email_body(body: str) -> dict:
    """
    Run the PII redactor on an email body.

    Returns dict with redacted text and report, or raises on failure.
    SECURITY: If redaction fails, we NEVER return raw content.
    """
    result = _redactor.redact(body)

    # FAIL CLOSED: if the redactor itself reported an error, reject the content
    if result.clean_text == "[REDACTION_ERROR: content withheld for safety]":
        raise RuntimeError("PII redaction failed — content withheld for safety")

    return {
        "redacted_body": result.clean_text,
        "redaction_report": {
            "redaction_count": result.redaction_count,
            "is_valid": result.is_valid,
            "validation_issues": result.validation_issues,
            "details": [
                {
                    "type": d.pattern_name,
                    "replacement": d.replacement,
                }
                for d in result.redaction_details
            ],
        },
    }


def _extract_merchant(sender: str, sender_email: str) -> str:
    """Extract merchant name from sender display name or email domain."""
    if sender and sender != sender_email:
        return sender
    # Fall back to domain name
    match = re.search(r"@([\w\-]+)\.", sender_email)
    if match:
        return match.group(1).replace("-", " ").title()
    return "Unknown"


def _extract_amounts(text: str) -> list[str]:
    """Extract all dollar amounts from text."""
    return _DOLLAR_PATTERN.findall(text)


@mcp.tool()
def fetch_financial_emails(days: int = 30, max_results: int = 50) -> str:
    """
    Fetch financial emails from Gmail and extract sanitized transaction data.

    SECURITY PIPELINE (runs entirely in MCP server):
    1. Fetch from Gmail API
    2. Apply blocklist (filter spam/promo)
    3. Apply PII redaction (3-pass pipeline)
    4. Extract transactions (regex-based, no LLM)
    5. Return ONLY sanitized transaction metadata

    The agent NEVER sees raw email bodies - only extracted transaction data.

    Args:
        days: Number of days to look back (default 30)
        max_results: Maximum number of emails to return (default 50, max 100)

    Returns:
        JSON string with transactions and pipeline statistics
    """
    import json
    from ..config.blocklist import get_blocklist
    from ..agent.extractor import extract_transaction
    from ..agent.tools import check_prompt_injection_raw, _infer_category_local

    max_results = min(max_results, int(os.getenv("MAX_EMAILS_PER_SCAN", "100")))

    # LAYER 1: Fetch from Gmail API
    try:
        client = _get_gmail_client()
        query = client.build_financial_query(days=days)
        email_list = client.search_emails(query, max_results=max_results)
        logger.info(f"📧 Fetched {len(email_list)} emails from Gmail")
    except Exception as e:
        logger.error("Gmail API error in fetch_financial_emails: %s", e)
        return json.dumps({"error": f"Failed to fetch emails: {e}", "transactions": [], "pipeline_stats": {}})

    # LAYER 2: Apply blocklist filter
    blocklist = get_blocklist()
    emails_after_blocklist = []
    blocked_count = 0

    for email_meta in email_list:
        sender = email_meta.get("sender", "")
        subject = email_meta.get("subject", "")
        is_blocked, reason = blocklist.is_blocked(sender, subject)

        if is_blocked:
            blocked_count += 1
            logger.debug(f"Blocked email by {reason}: {subject[:50]}")
        else:
            emails_after_blocklist.append(email_meta)

    logger.info(f"🚫 Blocklist filtered out {blocked_count}/{len(email_list)} emails")
    email_list = emails_after_blocklist

    # LAYER 3: PII Redaction + LAYER 4: Transaction Extraction
    transactions = []
    total_redactions = 0
    injections_detected = 0
    failed_redaction_count = 0

    # Collect redaction statistics for demo display
    redaction_stats = RedactionStats()

    # Capture ONE before/after example for demo (THE MONEY SHOT)
    pii_example_before = None
    pii_example_after = None
    pii_example_count = 0

    for email_meta in email_list:
        try:
            full_email = client.get_email_body(email_meta["id"])
        except Exception as e:
            logger.error("Failed to fetch body for email %s: %s", email_meta["id"], e)
            continue

        # LAYER 3: PII Redaction - SECURITY: Redact BEFORE any processing
        try:
            # Get the full redaction result to collect stats
            redaction_result = _redactor.redact(full_email["body"])

            # FAIL CLOSED: if the redactor itself reported an error, reject the content
            if redaction_result.clean_text == "[REDACTION_ERROR: content withheld for safety]":
                raise RuntimeError("PII redaction failed — content withheld for safety")

            # Collect stats
            redaction_stats.add_result(redaction_result)
            total_redactions += redaction_result.redaction_count

            # Capture first email with VISIBLE PII redactions as the demo example
            if pii_example_before is None and redaction_result.redaction_count > 0 and redaction_result.redaction_details:
                # Get the first redaction detail to build before/after example
                first_redaction = redaction_result.redaction_details[0]

                # Strip HTML tags and collapse whitespace
                def strip_html(text: str) -> str:
                    """Remove HTML tags and collapse whitespace."""
                    clean = re.sub(r'<[^>]+>', ' ', text)
                    clean = re.sub(r'\s+', ' ', clean)
                    return clean.strip()

                original_stripped = strip_html(full_email["body"])
                redacted_stripped = strip_html(redaction_result.clean_text)

                # Find where the replacement tag appears in redacted text
                replacement_tag = first_redaction.replacement
                tag_pos = redacted_stripped.find(replacement_tag)

                if tag_pos != -1:
                    # Center snippet around the redaction tag (~100 chars context on each side)
                    start = max(0, tag_pos - 100)
                    end = min(len(redacted_stripped), tag_pos + len(replacement_tag) + 100)

                    after_snippet = redacted_stripped[start:end]

                    # For before snippet, try to find the original PII in the original text
                    # Use the original value from redaction detail if available
                    original_value = first_redaction.original if hasattr(first_redaction, 'original') and first_redaction.original else None

                    if original_value:
                        # Find original value in original text
                        orig_pos = original_stripped.find(original_value)
                        if orig_pos != -1:
                            # Use same window size around original PII
                            before_start = max(0, orig_pos - 100)
                            before_end = min(len(original_stripped), orig_pos + len(original_value) + 100)
                            before_snippet = original_stripped[before_start:before_end]

                            # Add ellipsis markers
                            if before_start > 0:
                                before_snippet = "..." + before_snippet
                            if before_end < len(original_stripped):
                                before_snippet = before_snippet + "..."
                        else:
                            # Fallback: use same position (may not align perfectly but better than nothing)
                            before_snippet = original_stripped[start:end]
                            if start > 0:
                                before_snippet = "..." + before_snippet
                    else:
                        # Fallback: use same position
                        before_snippet = original_stripped[start:end]
                        if start > 0:
                            before_snippet = "..." + before_snippet

                    # Add ellipsis for after snippet
                    if start > 0:
                        after_snippet = "..." + after_snippet
                    if end < len(redacted_stripped):
                        after_snippet = after_snippet + "..."
                        if original_value and orig_pos != -1 and before_end < len(original_stripped):
                            before_snippet = before_snippet + "..."

                    # Only use if they're visibly different
                    if before_snippet != after_snippet and len(before_snippet) > 20:
                        pii_example_before = before_snippet
                        pii_example_after = after_snippet
                        pii_example_count = redaction_result.redaction_count

            # LAYER 4: Prompt Injection Detection
            redacted_body = redaction_result.clean_text
            injection_result = check_prompt_injection_raw(redacted_body)
            if injection_result["is_suspicious"]:
                injections_detected += 1
                logger.warning(f"⚠️  Injection detected in email {email_meta['id']}: {injection_result['patterns_found']}")

            # LAYER 4: Transaction Extraction (regex-based, no LLM)
            email_for_extraction = {
                "id": email_meta["id"],
                "sender": email_meta.get("sender", ""),
                "subject": email_meta.get("subject", ""),
                "date": email_meta.get("date", ""),
                "body": redacted_body,  # Already sanitized
            }

            extracted = extract_transaction(email_for_extraction)
            if extracted:
                # Quick categorization using local keyword matching
                category = _infer_category_local(
                    extracted.get("merchant", ""),
                    email_meta.get("subject", "")
                )

                transaction = {
                    "source_email_id": extracted.get("email_id", ""),
                    "merchant": extracted.get("merchant", "Unknown"),
                    "amount": extracted.get("amount", 0.0),
                    "date": extracted.get("date", email_meta.get("date", "")),
                    "category": category,
                    "payment_method_type": extracted.get("payment_method_type"),
                    "subject": email_meta.get("subject", ""),
                }
                transactions.append(transaction)

        except RuntimeError:
            # FAIL CLOSED: redaction failed, skip this email entirely
            failed_redaction_count += 1
            logger.error(
                "Redaction failed for email %s — content withheld", email_meta["id"]
            )
            continue

        # Discard the raw body — it must not persist beyond this function
        del full_email

    # Calculate total amount
    total_amount = sum(t["amount"] for t in transactions)

    # Return as JSON string (MCP tools return strings)
    result = {
        "transactions": transactions,
        "total_transactions": len(transactions),
        "total_amount": total_amount,
        "pipeline_stats": {
            "fetched": len(email_list) + blocked_count,  # Original count before blocklist
            "blocked": blocked_count,
            "redacted": total_redactions,
            "failed_closed": failed_redaction_count,
            "injections": injections_detected,
            "extracted": len(transactions),
        },
        "redaction_stats": {
            "total_emails": redaction_stats.total_emails,
            "total_redactions": redaction_stats.total_redactions,
            "by_type": dict(redaction_stats.by_type),
            "by_pass": dict(redaction_stats.by_pass),
            "failed_emails": redaction_stats.failed_emails,
        },
        "pii_example": {
            "before": pii_example_before,
            "after": pii_example_after,
            "redaction_count": pii_example_count,
        } if pii_example_before else None,
        "query_days": days,
    }

    logger.info(f"✅ Extracted {len(transactions)} transactions, total: ${total_amount:.2f}")
    return json.dumps(result)


@mcp.tool()
def get_email_detail(email_id: str) -> dict:
    """
    Fetch a single email by ID with full PII redaction.

    Args:
        email_id: The Gmail message ID

    Returns:
        Sanitized email with: id, sender, subject, date, redacted_body, redaction_report
    """
    try:
        client = _get_gmail_client()
        full_email = client.get_email_body(email_id)
    except Exception as e:
        logger.error("Gmail API error in get_email_detail: %s", e)
        return {"error": f"Failed to fetch email {email_id}: {e}"}

    # SECURITY: Redact BEFORE returning
    try:
        redacted = _redact_email_body(full_email["body"])
    except RuntimeError:
        logger.error("Redaction failed for email %s — content withheld", email_id)
        return {
            "id": email_id,
            "error": "Redaction failed — content withheld for safety",
        }

    result = {
        "id": full_email["id"],
        "sender": full_email["sender"],
        "sender_email": full_email["sender_email"],
        "subject": full_email["subject"],
        "date": full_email["date"],
        "redacted_body": redacted["redacted_body"],
        "redaction_report": redacted["redaction_report"],
        "audit_summary": (
            f"Email {email_id} accessed, "
            f"{redacted['redaction_report']['redaction_count']} redactions applied"
        ),
    }

    # Discard raw body
    del full_email

    return result


@mcp.tool()
def get_financial_summary(days: int = 7) -> dict:
    """
    Get a structured financial summary for the given period.

    Fetches all financial emails, redacts PII, then extracts
    structured data: date, merchant, amounts, category hints.

    Args:
        days: Number of days to look back (default 7)

    Returns:
        List of {date, merchant, amount, category_hint} entries
    """
    try:
        client = _get_gmail_client()
        query = client.build_financial_query(days=days)
        max_results = int(os.getenv("MAX_EMAILS_PER_SCAN", "100"))
        email_list = client.search_emails(query, max_results=max_results)
    except Exception as e:
        logger.error("Gmail API error in get_financial_summary: %s", e)
        return {"error": f"Failed to fetch emails: {e}", "transactions": []}

    # Apply blocklist filtering (same as scan_financial_emails tool)
    from ..config.blocklist import get_blocklist
    blocklist = get_blocklist()
    filtered_emails = []
    blocked_count = 0

    for email_meta in email_list:
        sender = email_meta.get("sender", "")
        subject = email_meta.get("subject", "")
        is_blocked, reason = blocklist.is_blocked(sender, subject)

        if is_blocked:
            blocked_count += 1
            logger.debug(f"Blocked email by {reason}: {subject[:50]}")
        else:
            filtered_emails.append(email_meta)

    logger.info(f"Blocklist filtered out {blocked_count}/{len(email_list)} emails")
    email_list = filtered_emails

    transactions = []
    total_redactions = 0

    for email_meta in email_list:
        try:
            full_email = client.get_email_body(email_meta["id"])
        except Exception as e:
            logger.error("Failed to fetch body for email %s: %s", email_meta["id"], e)
            continue

        # SECURITY: Redact first
        try:
            redacted = _redact_email_body(full_email["body"])
        except RuntimeError:
            logger.error(
                "Redaction failed for email %s — skipping", email_meta["id"]
            )
            continue

        total_redactions += redacted["redaction_report"]["redaction_count"]
        redacted_body = redacted["redacted_body"]

        # Extract structured data from the redacted (safe) content
        amounts = _extract_amounts(redacted_body)
        merchant = _extract_merchant(
            email_meta.get("sender", ""),
            email_meta.get("sender_email", email_meta.get("sender", "")),
        )
        category_hint = _infer_category(
            email_meta.get("subject", ""), merchant
        )

        transactions.append(
            {
                "date": email_meta.get("date", ""),
                "merchant": merchant,
                "amounts": amounts,
                "subject": email_meta.get("subject", ""),
                "category_hint": category_hint,
                "email_id": email_meta["id"],
            }
        )

        # Discard raw body
        del full_email

    return {
        "transactions": transactions,
        "total_transactions": len(transactions),
        "total_redactions": total_redactions,
        "pipeline_stats": {
            "fetched": len(email_list) + blocked_count,  # Original count before blocklist
            "blocked": blocked_count,
            "redacted": total_redactions,
            "injections": 0,  # Not tracked in this function
            "extracted": len(transactions),
        },
        "query_days": days,
        "audit_summary": (
            f"{len(transactions)} financial transactions found over {days} days, "
            f"{total_redactions} PII items redacted"
        ),
    }


def _infer_category(subject: str, merchant: str) -> str:
    """Infer a spending category from the email subject and merchant."""
    text = f"{subject} {merchant}".lower()

    # Check credit card companies first (priority patterns)
    credit_card_issuers = ["discover", "chase", "capital one", "citi", "citibank",
                           "amex", "american express", "bank of america"]

    if any(issuer in text for issuer in credit_card_issuers):
        # Cashback/rewards are Income
        if any(word in text for word in ["cashback", "cash back", "reward", "bonus", "rebate"]):
            return "income"
        # Payments/statements are Bills
        if any(word in text for word in ["payment received", "payment confirmation",
                                          "thank you for your payment", "statement",
                                          "balance due", "minimum payment", "amount due"]):
            return "bills"
        # Default for credit card issuers is Bills
        return "bills"

    category_keywords = {
        "subscription": ["netflix", "spotify", "hulu", "disney", "subscription", "renewed", "membership"],
        "food_delivery": ["doordash", "grubhub", "ubereats", "postmates"],
        "rideshare": ["uber", "lyft", "ride"],
        "shopping": ["amazon", "order", "shipped", "delivered", "purchase"],
        "groceries": ["whole foods", "trader joe", "grocery", "safeway", "kroger"],
        "dining": ["restaurant", "dinner", "lunch", "cafe", "nobu"],
        "transfer": ["venmo", "zelle", "cashapp", "transfer", "sent", "received", "payment"],
        "gas": ["shell", "chevron", "gas", "fuel", "exxon"],
        "bills": ["statement", "bill", "due", "balance", "payment due"],
        "income": ["cashback", "cash back", "reward", "refund", "reimbursement"],
    }

    for category, keywords in category_keywords.items():
        if any(kw in text for kw in keywords):
            return category

    return "other"

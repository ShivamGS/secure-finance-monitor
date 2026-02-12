"""
PII regex patterns for the redaction pipeline.

Each pattern is a compiled regex paired with a name and replacement function/template.
Order matters: more specific patterns (credit cards, SSNs) are applied before
generic catch-all patterns to avoid double-redaction.
"""

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class PIIPattern:
    name: str
    regex: re.Pattern
    replacement: Callable[[re.Match], str]
    priority: int  # lower = applied first


def _replace_credit_card(match: re.Match) -> str:
    """Replace credit card number, keeping only last 4 digits."""
    full = re.sub(r"[\s\-]", "", match.group(0))
    last4 = full[-4:]
    return f"[CARD_****{last4}]"


def _replace_account_number(match: re.Match) -> str:
    prefix = match.group("prefix")
    return f"{prefix}[ACCT_REDACTED]"


def _replace_routing_number(match: re.Match) -> str:
    prefix = match.group("prefix")
    return f"{prefix}[ROUTING_REDACTED]"


def _replace_ssn(match: re.Match) -> str:
    return "[SSN_REDACTED]"


def _replace_phone(match: re.Match) -> str:
    return "[PHONE_REDACTED]"


def _replace_address(match: re.Match) -> str:
    return "[ADDRESS_REDACTED]"


def _replace_email(match: re.Match) -> str:
    return "[EMAIL_REDACTED]"


def _replace_secure_url(match: re.Match) -> str:
    return "[SECURE_URL_REDACTED]"


def _replace_generic_long_number(match: re.Match) -> str:
    prefix = match.group("prefix")
    return f"{prefix}[NUMBER_REDACTED]"


# ---------------------------------------------------------------------------
# Pattern definitions (ordered by priority — lower number = applied first)
# ---------------------------------------------------------------------------

# Credit/debit card numbers
# Visa: starts with 4, 13 or 16 digits
# Mastercard: starts with 5[1-5] or 2[2-7]xx, 16 digits
# Amex: starts with 3[47], 15 digits
# Discover: starts with 6011 or 65, 16 digits
# Supports: 4532882100934892, 4532-8821-0093-4892, 4532 8821 0093 4892
CREDIT_CARD = PIIPattern(
    name="credit_card",
    regex=re.compile(
        r"(?<!\d)"
        r"(?:"
        # Visa 16-digit
        r"4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"
        r"|"
        # Mastercard
        r"(?:5[1-5]\d{2}|2[2-7]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"
        r"|"
        # Amex
        r"3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}"
        r"|"
        # Discover
        r"(?:6011|65\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"
        r")"
        r"(?!\d)"
    ),
    replacement=_replace_credit_card,
    priority=10,
)

# Masked card patterns like ****4892 — preserve as-is (already masked)
MASKED_CARD = PIIPattern(
    name="masked_card",
    regex=re.compile(
        r"\*{3,4}[\-]?\d{4}\b"
    ),
    replacement=lambda m: m.group(0),  # preserve — already masked
    priority=5,
)

# SSN: XXX-XX-XXXX (including partial masks like ***-**-6781)
SSN = PIIPattern(
    name="ssn",
    regex=re.compile(
        r"\b\d{3}\-\d{2}\-\d{4}\b"
        r"|"
        r"\*{3}\-\*{2}\-\d{4}\b"
    ),
    replacement=_replace_ssn,
    priority=20,
)

# Routing numbers: 9 digits near "routing" keyword
ROUTING_NUMBER = PIIPattern(
    name="routing_number",
    regex=re.compile(
        r"(?P<prefix>(?:routing|aba|transit)[\s#:]*)"
        r"\d{9}\b",
        re.IGNORECASE,
    ),
    replacement=_replace_routing_number,
    priority=25,
)

# Bank account numbers: 8-17 digit sequences near financial keywords
ACCOUNT_NUMBER = PIIPattern(
    name="account_number",
    regex=re.compile(
        r"(?P<prefix>(?:account|acct|acct\.)[\s#:]*(?:number[\s#:]*|num[\s#:]*|no[\s#:]*)?)"
        r"\d{8,17}\b",
        re.IGNORECASE,
    ),
    replacement=_replace_account_number,
    priority=30,
)

# Phone numbers (US formats)
# (415) 555-8291, 415-555-8291, 415.555.8291, 1-800-935-9935
PHONE_NUMBER = PIIPattern(
    name="phone_number",
    regex=re.compile(
        r"\b1[\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b"
        r"|"
        r"\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b"
    ),
    replacement=_replace_phone,
    priority=40,
)

# Email addresses in body text
EMAIL_ADDRESS = PIIPattern(
    name="email_address",
    regex=re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    replacement=_replace_email,
    priority=50,
)

# URLs with auth tokens (token=, session=, auth=, password=, key=, id= params)
SECURE_URL = PIIPattern(
    name="secure_url",
    regex=re.compile(
        r"https?://[^\s]+[?&](?:token|session|auth|password|key|id)=[^\s]*",
        re.IGNORECASE,
    ),
    replacement=_replace_secure_url,
    priority=45,
)

# Physical addresses: number + street + optional apt + city, STATE ZIP
ADDRESS = PIIPattern(
    name="address",
    regex=re.compile(
        r"\b\d{1,6}\s+[A-Za-z0-9\.\s]{2,40}"
        r"(?:,?\s*(?:Apt|Suite|Ste|Unit|#)\s*[A-Za-z0-9]+)?"
        r",?\s*[A-Za-z\s]{2,30},?\s*[A-Z]{2}\s+\d{5}(?:\-\d{4})?\b"
    ),
    replacement=_replace_address,
    priority=55,
)

# Generic long numbers (10+ digits) near financial keywords
GENERIC_LONG_NUMBER = PIIPattern(
    name="generic_long_number",
    regex=re.compile(
        r"(?P<prefix>(?:order|confirmation|reference|tracking|transaction|member|policy|claim|invoice)[\s#:]*)"
        r"[\d\-]{10,}\b",
        re.IGNORECASE,
    ),
    replacement=_replace_generic_long_number,
    priority=35,  # before phone (40) so "Order #114-..." isn't split by phone pattern
)


def get_patterns_ordered() -> list[PIIPattern]:
    """Return all PII patterns ordered by priority (most specific first)."""
    patterns = [
        MASKED_CARD,
        CREDIT_CARD,
        SSN,
        ROUTING_NUMBER,
        ACCOUNT_NUMBER,
        PHONE_NUMBER,
        SECURE_URL,
        EMAIL_ADDRESS,
        ADDRESS,
        GENERIC_LONG_NUMBER,
    ]
    return sorted(patterns, key=lambda p: p.priority)

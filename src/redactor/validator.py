"""
Post-redaction validator — the final safety net.

Scans redacted text for any sequences that still look like PII.
If anything suspicious slips through both regex and Presidio passes,
this layer catches it and replaces it with [UNKNOWN_PII_REDACTED].
"""

import re
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    is_valid: bool
    issues: list[str] = field(default_factory=list)
    cleaned_text: str = ""
    fixes_applied: int = 0


# Patterns that should NOT appear in clean output (outside of redaction tags).
# We look for suspicious sequences that weren't caught by prior passes.
_LEAK_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Untagged numeric sequences of 6+ digits (not inside brackets, not a dollar amount)
    (
        "long_number",
        re.compile(
            r"(?<!\[)"           # not preceded by [
            r"(?<!\$)"           # not preceded by $
            r"(?<!,)"            # not preceded by comma (part of dollar amounts)
            r"\b\d{6,}\b"
            r"(?!\])"            # not followed by ]
        ),
    ),
    # SSN-like: 3-2-4 digit pattern
    (
        "ssn_like",
        re.compile(r"(?<!\[)\b\d{3}\-\d{2}\-\d{4}\b(?!\])"),
    ),
    # Partial SSN: **-XXXX pattern
    (
        "partial_ssn",
        re.compile(r"\*+\-\*+\-\d{4}"),
    ),
    # Untagged email-like
    (
        "email_like",
        re.compile(
            r"(?<!\[)"
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
            r"(?!\])"
        ),
    ),
    # Phone-like: (XXX) XXX-XXXX or XXX-XXX-XXXX
    (
        "phone_like",
        re.compile(
            r"(?<!\[)"
            r"\(?\d{3}\)?[\s\-\.]\d{3}[\s\-\.]\d{4}"
            r"(?!\])"
        ),
    ),
]

# Sequences that are OK to keep (dollar amounts, dates, redaction tags, etc.)
_SAFE_PATTERNS = [
    re.compile(r"\$[\d,]+\.?\d*"),                  # dollar amounts
    re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b"),    # dates MM/DD/YYYY
    re.compile(r"\b\d{1,2}\-\d{1,2}\-\d{2,4}\b"),  # dates MM-DD-YYYY
    re.compile(r"\[[\w\*_]+\]"),                     # redaction tags
    re.compile(r"#\d+"),                             # order/store numbers like #1247
    re.compile(r"\b\d{1,2}:\d{2}\b"),               # times like 2:15
    re.compile(r"\b\d{5}(?:\-\d{4})?\b"),           # ZIP codes (5 or 5-4 digits)
]


def _is_safe_context(text: str, match: re.Match) -> bool:
    """Check if a suspicious match is actually safe (dollar amount, date, etc.)."""
    start, end = match.start(), match.end()
    matched_text = match.group(0)

    for safe in _SAFE_PATTERNS:
        # Check if this match is contained within a safe pattern
        for safe_match in safe.finditer(text):
            s, e = safe_match.start(), safe_match.end()
            if s <= start and end <= e:
                return True

    # ZIP codes: 5-digit numbers are likely zip codes, allow them
    if re.fullmatch(r"\d{5}", matched_text):
        return True

    return False


def validate(text: str) -> ValidationResult:
    """
    Scan redacted text for any remaining PII-like sequences.

    Returns a ValidationResult with is_valid=True if clean,
    or is_valid=False with details and a further-cleaned version.
    """
    result = ValidationResult(is_valid=True, cleaned_text=text)

    for pattern_name, pattern in _LEAK_PATTERNS:
        # Work on the latest cleaned text
        current = result.cleaned_text
        new_text = current
        offset = 0

        for match in pattern.finditer(current):
            if _is_safe_context(current, match):
                continue

            # This looks like leaked PII
            result.is_valid = False
            result.issues.append(
                f"{pattern_name}: '{match.group(0)}' at position {match.start()}"
            )

            # Replace it
            start = match.start() + offset
            end = match.end() + offset
            replacement = "[UNKNOWN_PII_REDACTED]"
            new_text = new_text[:start] + replacement + new_text[end:]
            offset += len(replacement) - (match.end() - match.start())
            result.fixes_applied += 1

        result.cleaned_text = new_text

    return result

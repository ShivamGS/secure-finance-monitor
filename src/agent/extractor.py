"""
Smart transaction extraction from redacted emails.

Extracts merchant names, amounts, dates, and payment methods using
regex patterns and keyword matching - NO LLM needed for basic extraction.
"""

import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Promotional email indicators (subject patterns)
PROMO_SUBJECT_PATTERNS = [
    r'\b(?:sale|deal|offer|discount|save|off)\b',
    r'\b\d+%\s*off\b',
    r'\binvite(?:\s*only|-only)\b',
    r'\breward\s*points?\b',
    r'\bapply\s*now\b',
    r'\bjob\s*(?:alert|opening)\b',
    r'\blimited\s*time\b',
    r'\bexclusive\s*(?:deal|offer)\b',
    r'\bfree\s*(?:shipping|trial|gift)\b',
    r'\bnew\s*arrivals?\b',
    r'\bshop\s*now\b',
    r'\bflash\s*sale\b',
    r'\bclearance\b',
    r'\bspring\s*break\b',
    r'\bready,?\s*set\b',
    r'\bcheck\s*out\s*(?:these|our)\b',
    r'\bdon\'t\s*miss\b',
    r'\b\d+\s*months?\s*(?:of|free)\b',  # "5 months of Uber One"
]

# Promotional body patterns
PROMO_BODY_PATTERNS = [
    r'unsubscribe',
    r'manage\s*(?:your\s*)?preferences',
    r'click\s*here\s*to\s*(?:shop|save|claim)',
    r'promotional\s*(?:email|offer)',
]

# Non-transaction keywords (informational emails)
NON_TRANSACTION_PATTERNS = [
    r'security\s*alert',
    r'sign[-\s]in\s*(?:detected|alert)',
    r'password\s*(?:reset|changed)',
    r'credit\s*(?:score|journey|summary)',  # Credit monitoring emails
    r'your\s+credit\s+score',  # Task 7: Cequence demo enhancement
    r'account\s*statement',  # Monthly statements, not transactions
    r'annual\s+fee',  # Task 7: Annual fee notifications
    r'apply\s+now',  # Task 7: Application prompts
    r'pre[-\s]?approved',  # Pre-approved offers
    r'tips?\s*(?:and|&)\s*updates?',
    r'welcome\s*to\s*google',
    r'review\s*your\s*(?:account\s*)?settings',
    r'(?:out|in)\s+for\s+delivery',  # Delivery tracking notifications
    r'your\s+delivery\s+(?:should|will)\s+arrive',  # Delivery ETAs
    r'track\s+(?:your\s+)?(?:order|package|shipment)',
    r'billing\s+document\s+available',  # Statement notifications
    r'credit\s+limit\s+increase',  # Credit limit offers
]

# Merchant-specific promotional senders (always promotional, never transactions)
ALWAYS_PROMOTIONAL_MERCHANTS = [
    'ziprecruiter',
    'indeed',
    'linkedin jobs',
    'job alert',
    'career',
    'groupon',  # Usually deals/offers, not actual purchases
]


def _is_promotional_email(subject: str, body: str, merchant: str = "") -> bool:
    """Check if email is promotional/marketing rather than a transaction."""
    subject_lower = subject.lower()
    body_lower = body[:500].lower()  # Check first 500 chars
    merchant_lower = merchant.lower()

    # Check if merchant is always promotional (job sites, deal sites)
    for promo_merchant in ALWAYS_PROMOTIONAL_MERCHANTS:
        if promo_merchant in merchant_lower:
            return True

    # Check subject for promo patterns
    for pattern in PROMO_SUBJECT_PATTERNS:
        if re.search(pattern, subject_lower, re.IGNORECASE):
            return True

    # Check for non-transaction patterns (informational emails)
    for pattern in NON_TRANSACTION_PATTERNS:
        if re.search(pattern, subject_lower, re.IGNORECASE):
            return True

    # Check body for promo indicators
    for pattern in PROMO_BODY_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return True

    return False


def _has_confirmation_keywords(subject: str, body: str) -> bool:
    """Check if email has transaction confirmation keywords (vs promotional)."""
    text = f"{subject} {body[:500]}".lower()

    # Confirmation indicators (actual transactions)
    confirmation_patterns = [
        r'\b(?:you\s+(?:purchased|paid|ordered|booked))\b',
        r'\b(?:order|booking|purchase|payment)\s+(?:confirmed|confirmation)\b',
        r'\b(?:receipt|invoice)\s+for\s+your\b',
        r'\btransaction\s+(?:alert|notification)\b',
        r'\b(?:charged|billed)\s+\$',
        r'\byour\s+card\s+(?:ending|was\s+charged)',
    ]

    for pattern in confirmation_patterns:
        if re.search(pattern, text):
            return True

    return False


def extract_transaction(email: dict) -> Optional[dict]:
    """
    Extract transaction details from a redacted email.

    Args:
        email: Dictionary with keys: id, sender, subject, date, body

    Returns:
        Dictionary with extracted transaction data or None if no financial data found:
        {
            "email_id": str,
            "merchant": str,
            "amount": float,
            "date": str (ISO format),
            "payment_method_type": str (optional),
            "items": list[str] (optional)
        }
    """
    if not email or not email.get('body'):
        return None

    body = email.get('body', '')
    subject = email.get('subject', '')
    sender = email.get('sender', '')
    email_date = email.get('date', '')

    # Early promotional check (subject/body patterns only)
    if _is_promotional_email(subject, body):
        logger.debug(f"Skipping promotional email (subject/body): {subject[:50]}")
        return None

    # Task 7: Check for "unsubscribe" in last 500 chars with no amounts in first 1000 chars
    # This catches marketing emails with prices mentioned late in the email
    if len(body) > 1000 and 'unsubscribe' in body[-500:].lower():
        # Check if there are no amounts in first 1000 chars
        first_1000 = body[:1000]
        amounts_in_start = _extract_amounts(first_1000, "")
        if not amounts_in_start:
            logger.debug(f"Skipping marketing email (unsubscribe footer, no early amounts): {subject[:50]}")
            return None

    # Extract merchant
    merchant = _extract_merchant(sender, subject, body)
    if not merchant:
        logger.debug(f"Could not extract merchant from email {email.get('id', 'unknown')}")
        return None

    # Merchant-specific promotional check
    if _is_promotional_email(subject, body, merchant):
        logger.debug(f"Skipping promotional email (merchant): {merchant}")
        return None

    # Extract amounts
    amounts = _extract_amounts(body, subject)
    if not amounts:
        logger.debug(f"No amounts found in email from {merchant}")
        logger.debug(f"  Subject: {subject[:100]}")
        logger.debug(f"  Body (first 300 chars): {body[:300]}")
        return None

    # Pick the largest amount as the total (handles subtotal, tax, total)
    amount = max(amounts)

    # For large amounts without confirmation keywords, be suspicious
    # (Likely promotional "Book for $3000" vs actual "You booked for $3000")
    if amount > 500 and not _has_confirmation_keywords(subject, body):
        logger.debug(f"Skipping high-value email without confirmation keywords: {merchant} ${amount}")
        return None

    # Extract date (use normalized email date as fallback)
    transaction_date = _extract_date(body)
    if not transaction_date:
        transaction_date = _normalize_email_date(email_date)

    # Extract payment method type (if mentioned)
    payment_method = _extract_payment_method(body)

    return {
        "email_id": email.get('id', ''),
        "merchant": merchant,
        "amount": amount,
        "date": transaction_date,
        "payment_method_type": payment_method,
    }


def _extract_merchant(sender: str, subject: str, body: str) -> Optional[str]:
    """
    Extract merchant name from sender, subject, or body.

    Tries multiple patterns in order of reliability.
    """
    # 1. From sender name (most reliable)
    # "Walmart <no-reply@walmart.com>" → "Walmart"
    if sender and not sender.startswith('no-reply') and not sender.startswith('noreply'):
        # Clean up sender name
        merchant = sender.split('<')[0].strip()
        merchant = merchant.replace('"', '').strip()
        if merchant and len(merchant) > 2:
            return merchant[:50]  # Limit length

    # 2. From subject line
    # "Your Walmart.com order" → "Walmart"
    # "Receipt from The Event Palette" → "The Event Palette"
    subject_patterns = [
        r'receipt from ([^,\n]+)',
        r'order from ([^,\n]+)',
        r'payment to ([^,\n]+)',
        r'your ([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*) (?:order|receipt|subscription)',
        r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*) order confirmation',
        r'thank you for.*?(?:shopping|order).*?at ([A-Z][a-z]+)',
    ]

    for pattern in subject_patterns:
        match = re.search(pattern, subject, re.IGNORECASE)
        if match:
            merchant = match.group(1).strip()
            if merchant and len(merchant) > 2:
                return merchant[:50]

    # 3. From body text
    body_patterns = [
        r'receipt from ([^\n,]+)',
        r'order from ([^\n,]+)',
        r'sold (?:locally )?by ([^\n,]+)',
        r'merchant:\s*([^\n,]+)',
        r'payment to ([^\n,]+)',
        r'purchased at ([^\n,]+)',
        r'you paid ([^\n,]+) \$',
    ]

    # Only search first 800 chars of body for performance
    body_snippet = body[:800]

    for pattern in body_patterns:
        match = re.search(pattern, body_snippet, re.IGNORECASE)
        if match:
            merchant = match.group(1).strip()
            # Clean up
            merchant = merchant.split('\n')[0].strip()
            merchant = re.sub(r'\s+', ' ', merchant)
            if merchant and len(merchant) > 2:
                return merchant[:50]

    # 4. Fallback to sender email domain
    # "walmart.com" → "Walmart"
    if '@' in sender:
        email_part = sender.split('<')[-1].strip('>')
        domain = email_part.split('@')[-1]
        domain_name = domain.split('.')[0]
        if domain_name and len(domain_name) > 2:
            return domain_name.capitalize()[:50]

    return None


def _extract_amounts(text: str, subject: str = "") -> list[float]:
    """
    Extract dollar amounts from text.

    Handles multiple formats:
    - $39.88
    - $ 39.88
    - $1,234.56
    - 39.88 USD
    - Amount: $27.20
    - Total: $39.88
    """
    amounts = []

    # Combine subject and body for amount extraction
    full_text = f"{subject}\n{text}"

    # Pattern for various amount formats
    patterns = [
        r'\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)',  # $123.45 or $1,234.56 or $39
        r'(\d{1,3}(?:,\d{3})*\.\d{2})\s*USD',  # 123.45 USD
        r'(?:total|amount|paid|charge|price|cost|subtotal|grand\s+total)[\s:]+\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)',
        r'(?:you paid|you\'re paying|payment of)[\s:]+\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)',
        r'(?:order total|total due|amount due)[\s:]+\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, full_text, re.IGNORECASE)
        for match in matches:
            try:
                # Remove commas and convert to float
                amount_str = match.replace(',', '')
                amount = float(amount_str)
                # Filter out unrealistic amounts (too small or too large)
                if 0.01 <= amount <= 999999:
                    amounts.append(amount)
            except (ValueError, AttributeError):
                continue

    return sorted(set(amounts))  # Remove duplicates and sort


def _extract_date(text: str) -> Optional[str]:
    """
    Extract transaction date from email body.

    Returns YYYY-MM-DD format date string or None.
    """
    # Look in first 500 chars where date is usually mentioned
    text_snippet = text[:500]

    # Date patterns
    patterns = [
        r'date(?:\s+paid)?:\s*([A-Z][a-z]{2}\s+\d{1,2},?\s+\d{4})',  # Feb 8, 2026
        r'(\d{1,2}/\d{1,2}/\d{4})',  # 02/08/2025
        r'(\d{4}-\d{2}-\d{2})',  # 2026-02-11
        r'([A-Z][a-z]{2,8}\s+\d{1,2},?\s+\d{4})',  # February 8, 2026
    ]

    for pattern in patterns:
        match = re.search(pattern, text_snippet, re.IGNORECASE)
        if match:
            date_str = match.group(1)
            try:
                # Try to parse and convert to YYYY-MM-DD format
                # Handle different formats
                for fmt in ['%b %d, %Y', '%m/%d/%Y', '%Y-%m-%d', '%B %d, %Y']:
                    try:
                        dt = datetime.strptime(date_str, fmt)
                        return dt.strftime('%Y-%m-%d')  # Return YYYY-MM-DD
                    except ValueError:
                        continue
            except Exception:
                continue

    return None


def _normalize_email_date(date_str: str) -> str:
    """
    Normalize Gmail Date header to YYYY-MM-DD format.

    Handles formats like:
    - "Wed, 11 Feb 2026 10:30:00 -0800" (RFC 2822)
    - "2026-02-11T10:30:00Z" (ISO 8601)
    - "Wed, 11 Fe" (truncated)
    """
    if not date_str:
        return datetime.now().strftime('%Y-%m-%d')

    # If already in YYYY-MM-DD format, return as-is
    if re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        return date_str

    # Try ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
    if re.match(r'^\d{4}-\d{2}-\d{2}T', date_str):
        return date_str[:10]

    # Try RFC 2822 format (Day, DD Mon YYYY HH:MM:SS)
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        return dt.strftime('%Y-%m-%d')
    except Exception:
        pass

    # Fallback: try common formats
    for fmt in ['%a, %d %b %Y', '%d %b %Y', '%b %d, %Y', '%m/%d/%Y']:
        try:
            dt = datetime.strptime(date_str.split()[0:3] if ' ' in date_str else date_str, fmt)
            return dt.strftime('%Y-%m-%d')
        except (ValueError, IndexError):
            continue

    # Last resort: return today's date
    logger.warning(f"Could not parse date '{date_str}', using today")
    return datetime.now().strftime('%Y-%m-%d')


def _extract_payment_method(text: str) -> Optional[str]:
    """
    Extract payment method type from email body.

    Returns payment type (e.g., "visa", "discover", "paypal") or None.
    Note: Card numbers are already redacted by PII redactor.
    """
    text_lower = text.lower()[:600]  # First 600 chars

    # Payment method patterns
    if 'visa' in text_lower and 'ending in' in text_lower:
        return 'visa'
    if 'discover' in text_lower and ('ending in' in text_lower or 'apple pay' in text_lower):
        return 'discover'
    if 'mastercard' in text_lower and 'ending in' in text_lower:
        return 'mastercard'
    if 'american express' in text_lower or 'amex' in text_lower:
        return 'amex'
    if 'paypal' in text_lower:
        return 'paypal'
    if 'apple pay' in text_lower:
        return 'apple_pay'
    if 'google pay' in text_lower:
        return 'google_pay'
    if 'venmo' in text_lower:
        return 'venmo'
    if 'zelle' in text_lower:
        return 'zelle'
    if 'cash app' in text_lower or 'cashapp' in text_lower:
        return 'cashapp'

    return None

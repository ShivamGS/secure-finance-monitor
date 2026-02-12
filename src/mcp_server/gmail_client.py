"""
Gmail API client for fetching financial emails.

Wraps the Gmail API with methods to search for financial emails,
fetch full message bodies, and build targeted search queries.
All operations are read-only by design.
"""

import base64
import logging
import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from googleapiclient.discovery import build

from .gmail_auth import get_credentials

# Try to import BeautifulSoup for smart HTML parsing
try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFUL_SOUP = True
except ImportError:
    HAS_BEAUTIFUL_SOUP = False
    logging.warning("BeautifulSoup not installed - HTML email parsing will be basic. Install with: pip install beautifulsoup4 lxml")

logger = logging.getLogger(__name__)

# Comprehensive financial senders to search for
DEFAULT_FINANCIAL_SENDERS = [
    # Banks
    "*@chase.com", "*@bankofamerica.com", "*@wellsfargo.com", "*@capitalone.com",
    "*@citibank.com", "*@discover.com", "*@usbank.com", "*@pnc.com",
    # Payment platforms
    "*@paypal.com", "*@venmo.com", "*@zelle.com", "*@zellepay.com",
    "*@cashapp.com", "*@cash.app", "*@square.com", "*@stripe.com",
    # E-commerce
    "*@amazon.com", "*@walmart.com", "*@target.com", "*@bestbuy.com",
    "*@costco.com", "*@homedepot.com", "*@lowes.com", "*@macys.com",
    "*@nordstrom.com", "*@ebay.com", "*@etsy.com",
    # Food delivery
    "*@doordash.com", "*@grubhub.com", "*@ubereats.com", "*@uber.com",
    "*@instacart.com", "*@postmates.com",
    # Subscriptions
    "*@spotify.com", "*@netflix.com", "*@hulu.com", "*@disneyplus.com",
    "*@apple.com", "*@google.com", "*@adobe.com", "*@microsoft.com",
    "*@dropbox.com", "*@openai.com",
    # Travel
    "*@airbnb.com", "*@booking.com", "*@expedia.com", "*@united.com",
    "*@delta.com", "*@southwest.com", "*@hilton.com", "*@marriott.com",
    # Ride sharing
    "*@lyft.com",
    # Utilities/Bills
    "*@t-mobile.com", "*@verizon.com", "*@att.com", "*@xfinity.com",
]

# Max chars to extract from email body to avoid context overflow
MAX_EMAIL_BODY_LENGTH = 1500


def _html_to_text(html: str) -> str:
    """
    Convert HTML to clean plain text using BeautifulSoup.

    Intelligently extracts text from HTML emails by:
    - Removing script, style, meta, link, img, svg tags entirely
    - Removing HTML comments and base64 data
    - Converting tables to readable text format
    - Preserving document structure with proper spacing
    - Truncating to avoid context overflow
    """
    if not html:
        return ""

    if not HAS_BEAUTIFUL_SOUP:
        # Fallback to basic tag stripping if BeautifulSoup not available
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()[:MAX_EMAIL_BODY_LENGTH]

    try:
        soup = BeautifulSoup(html, 'lxml')

        # Remove unwanted tags entirely
        for tag in soup(['script', 'style', 'head', 'meta', 'link', 'img', 'svg', 'noscript']):
            tag.decompose()

        # Remove HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            comment.extract()

        # Remove base64 data blocks
        for tag in soup.find_all(string=re.compile(r'data:image|Content-Transfer-Encoding:\s*base64', re.IGNORECASE)):
            tag.extract()

        # Convert tables to readable format
        for table in soup.find_all('table'):
            rows = []
            for tr in table.find_all('tr'):
                cells = []
                for td in tr.find_all(['td', 'th']):
                    text = td.get_text(strip=True)
                    if text:
                        cells.append(text)
                if cells:
                    rows.append(' | '.join(cells))
            if rows:
                table.replace_with('\n'.join(rows) + '\n')

        # Get text with proper spacing
        text = soup.get_text(separator='\n')

        # Clean up whitespace
        lines = [line.strip() for line in text.splitlines()]
        lines = [line for line in lines if line]  # Remove empty lines
        text = '\n'.join(lines)

        # Collapse multiple newlines
        text = re.sub(r'\n{3,}', '\n\n', text)

        # Truncate if too long
        if len(text) > MAX_EMAIL_BODY_LENGTH:
            text = text[:MAX_EMAIL_BODY_LENGTH] + "\n[...truncated]"

        return text

    except Exception as e:
        logger.warning(f"HTML parsing failed: {e}, falling back to basic extraction")
        # Fallback to basic tag stripping
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()[:MAX_EMAIL_BODY_LENGTH]


def _decode_body(data: str) -> str:
    """Decode a base64url-encoded Gmail message body."""
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _get_header(headers: list[dict], name: str) -> str:
    """Extract a header value by name from Gmail message headers."""
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


class GmailClient:
    """Read-only Gmail API client for financial email retrieval."""

    def __init__(
        self,
        credentials_path: str | None = None,
        token_path: str | None = None,
    ) -> None:
        creds = get_credentials(credentials_path, token_path)
        self._service = build("gmail", "v1", credentials=creds)

    def search_emails(
        self, query: str, max_results: int = 50
    ) -> list[dict]:
        """
        Search Gmail using a query string.

        Returns list of email metadata (no full body — saves API calls):
            {id, sender, sender_email, subject, date, snippet}
        """
        results = (
            self._service.users()
            .messages()
            .list(userId="me", q=query, maxResults=max_results)
            .execute()
        )

        messages = results.get("messages", [])
        if not messages:
            return []

        emails = []
        for msg_ref in messages:
            msg = (
                self._service.users()
                .messages()
                .get(
                    userId="me",
                    id=msg_ref["id"],
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date"],
                )
                .execute()
            )

            headers = msg.get("payload", {}).get("headers", [])
            from_raw = _get_header(headers, "From")
            sender, sender_email = self._parse_from(from_raw)

            emails.append(
                {
                    "id": msg["id"],
                    "sender": sender,
                    "sender_email": sender_email,
                    "subject": _get_header(headers, "Subject"),
                    "date": _get_header(headers, "Date"),
                    "snippet": msg.get("snippet", ""),
                }
            )

        return emails

    def get_email_body(self, email_id: str) -> dict:
        """
        Fetch the full email by ID and extract the plain text body.

        Prefers text/plain over text/html. If only HTML is available,
        strips tags to get text.

        Returns:
            {id, sender, sender_email, subject, date, body}
        """
        msg = (
            self._service.users()
            .messages()
            .get(userId="me", id=email_id, format="full")
            .execute()
        )

        headers = msg.get("payload", {}).get("headers", [])
        from_raw = _get_header(headers, "From")
        sender, sender_email = self._parse_from(from_raw)

        body = self._extract_body(msg.get("payload", {}))

        return {
            "id": msg["id"],
            "sender": sender,
            "sender_email": sender_email,
            "subject": _get_header(headers, "Subject"),
            "date": _get_header(headers, "Date"),
            "body": body,
        }

    def build_financial_query(
        self,
        days: int = 30,
        custom_senders: list[str] | None = None,
    ) -> str:
        """
        Build a Gmail search query targeting financial emails.

        Combines sender-based search with subject-based search to catch more emails.
        Filters to emails newer than the specified number of days.

        Returns:
            Gmail query string combining sender and subject filters
        """
        senders = list(DEFAULT_FINANCIAL_SENDERS)
        if custom_senders:
            senders.extend(custom_senders)

        # Sender-based search
        from_clauses = " OR ".join(f"from:{s}" for s in senders)

        # Subject-based search for financial keywords
        subject_keywords = [
            "receipt", "payment", "order", "invoice", "charged", "transaction",
            "statement", "subscription", "renewal", "confirmation", "purchase",
            "total", "paid", "billing"
        ]
        subject_clauses = " OR ".join(f"subject:{kw}" for kw in subject_keywords)

        # Combine with OR so we catch emails that match either senders OR subjects
        return f"(({from_clauses}) OR ({subject_clauses})) newer_than:{days}d"

    def _extract_body(self, payload: dict) -> str:
        """
        Extract plain text body from a Gmail message payload.

        Walks MIME parts looking for text/plain first, then text/html.
        Truncates to MAX_EMAIL_BODY_LENGTH to avoid context overflow.
        """
        try:
            # Simple body (no parts)
            if "body" in payload and payload["body"].get("data"):
                mime = payload.get("mimeType", "")
                data = payload["body"]["data"]
                if mime == "text/plain":
                    body = _decode_body(data)
                    return self._truncate_body(body)
                elif mime == "text/html":
                    html = _decode_body(data)
                    return _html_to_text(html)  # Already truncated in _html_to_text

            # Multipart — walk all parts
            parts = payload.get("parts", [])
            text_plain = ""
            text_html = ""

            for part in parts:
                mime = part.get("mimeType", "")
                data = part.get("body", {}).get("data", "")

                if mime == "text/plain" and data:
                    text_plain = _decode_body(data)
                elif mime == "text/html" and data:
                    text_html = _decode_body(data)

                # Recurse into nested multipart
                if part.get("parts"):
                    nested = self._extract_body(part)
                    if nested:
                        text_plain = text_plain or nested

            # Prefer plain text; fall back to stripped HTML
            if text_plain:
                return self._truncate_body(text_plain)
            if text_html:
                return _html_to_text(text_html)  # Already truncated

            return ""

        except Exception as e:
            logger.error(f"Failed to extract email body: {e}")
            return "[Email body extraction failed]"

    @staticmethod
    def _truncate_body(text: str) -> str:
        """Truncate email body to max length to avoid context overflow."""
        if len(text) > MAX_EMAIL_BODY_LENGTH:
            return text[:MAX_EMAIL_BODY_LENGTH] + "\n[...truncated]"
        return text

    @staticmethod
    def _parse_from(from_header: str) -> tuple[str, str]:
        """
        Parse a From header into (display_name, email_address).

        Handles formats:
            "John Doe <john@example.com>" → ("John Doe", "john@example.com")
            "john@example.com"            → ("john@example.com", "john@example.com")
        """
        match = re.match(r"^(.+?)\s*<(.+?)>$", from_header)
        if match:
            return match.group(1).strip().strip('"'), match.group(2).strip()
        return from_header.strip(), from_header.strip()

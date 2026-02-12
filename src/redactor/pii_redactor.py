"""
Three-pass PII redaction pipeline.

Pass 1: Regex-based redaction (patterns.py) — fast, deterministic
Pass 2: Presidio NER redaction — catches names, locations regex missed
Pass 3: Validation sweep — final safety net for anything that slipped through

No LLM is involved at any point. This runs entirely locally.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .patterns import PIIPattern, get_patterns_ordered
from .validator import validate, ValidationResult


@dataclass
class RedactionDetail:
    pattern_name: str
    original: str
    replacement: str
    start: int
    end: int


@dataclass
class RedactionResult:
    clean_text: str
    redaction_count: int
    redaction_details: list[RedactionDetail] = field(default_factory=list)
    is_valid: bool = True
    validation_issues: list[str] = field(default_factory=list)


@dataclass
class RedactionStats:
    """
    Aggregated statistics across multiple redaction operations.
    Used for pipeline display in Cequence demo.
    """
    total_emails: int = 0
    total_redactions: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_pass: dict[str, int] = field(default_factory=lambda: {"regex": 0, "presidio": 0, "validation": 0})
    failed_emails: int = 0

    def add_result(self, result: RedactionResult) -> None:
        """Add a RedactionResult to the aggregate statistics."""
        self.total_emails += 1

        if not result.is_valid:
            self.failed_emails += 1
            return

        self.total_redactions += result.redaction_count

        # Count by type (CARD, SSN, ACCOUNT, etc.)
        for detail in result.redaction_details:
            pattern_name = detail.pattern_name
            self.by_type[pattern_name] = self.by_type.get(pattern_name, 0) + 1

            # Track which pass caught it (basic heuristic based on pattern name)
            if "PRESIDIO" in pattern_name or "PERSON" in pattern_name or "LOCATION" in pattern_name:
                self.by_pass["presidio"] += 1
            elif "VALIDATION" in pattern_name:
                self.by_pass["validation"] += 1
            else:
                self.by_pass["regex"] += 1


class PIIRedactor:
    """Three-pass PII redaction engine."""

    def __init__(self) -> None:
        # Suppress noisy third-party loggers
        # Keep our src.* loggers at INFO, but silence presidio, googleapiclient, etc.
        logging.getLogger('presidio-analyzer').setLevel(logging.ERROR)
        logging.getLogger('presidio-anonymizer').setLevel(logging.ERROR)
        logging.getLogger('googleapiclient.discovery').setLevel(logging.ERROR)
        logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
        logging.getLogger('google.auth').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)

        self._patterns = get_patterns_ordered()
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

        # Presidio entity types to detect (names, locations that regex won't catch)
        self._presidio_entities = [
            "PERSON",
            "LOCATION",
            "DATE_TIME",
            "NRP",          # nationalities, religious, political groups
            "MEDICAL_LICENSE",
            "IP_ADDRESS",
            "US_BANK_NUMBER",
            "US_DRIVER_LICENSE",
            "US_ITIN",
            "US_PASSPORT",
            "US_SSN",
            "PHONE_NUMBER",
            "EMAIL_ADDRESS",
            "CREDIT_CARD",
            "IBAN_CODE",
            "URL",
        ]

        # Map Presidio entity types to our redaction tag style
        self._presidio_tag_map = {
            "PERSON": "[PERSON_REDACTED]",
            "LOCATION": "[LOCATION_REDACTED]",
            "DATE_TIME": None,  # we preserve dates
            "NRP": "[NRP_REDACTED]",
            "MEDICAL_LICENSE": "[LICENSE_REDACTED]",
            "IP_ADDRESS": "[IP_REDACTED]",
            "US_BANK_NUMBER": "[ACCT_REDACTED]",
            "US_DRIVER_LICENSE": "[LICENSE_REDACTED]",
            "US_ITIN": "[SSN_REDACTED]",
            "US_PASSPORT": "[PASSPORT_REDACTED]",
            "US_SSN": "[SSN_REDACTED]",
            "PHONE_NUMBER": "[PHONE_REDACTED]",
            "EMAIL_ADDRESS": "[EMAIL_REDACTED]",
            "CREDIT_CARD": "[CARD_REDACTED]",
            "IBAN_CODE": "[IBAN_REDACTED]",
            "URL": None,  # we handle URLs ourselves in regex pass
        }

    def redact(self, text: str) -> RedactionResult:
        """
        Run the full three-pass pipeline on input text.

        Returns RedactionResult with clean text and audit details.
        Never raises — returns best-effort result on any failure.
        """
        try:
            details: list[RedactionDetail] = []

            # Pass 1: Regex
            text_after_regex, regex_details = self._pass_regex(text)
            details.extend(regex_details)

            # Pass 2: Presidio NER
            text_after_presidio, presidio_details = self._pass_presidio(text_after_regex)
            details.extend(presidio_details)

            # Pass 3: Validation
            validation = validate(text_after_presidio)
            final_text = validation.cleaned_text

            return RedactionResult(
                clean_text=final_text,
                redaction_count=len(details) + validation.fixes_applied,
                redaction_details=details,
                is_valid=validation.is_valid,
                validation_issues=validation.issues,
            )
        except Exception:
            # Safety fallback: if anything breaks, return heavily redacted output
            # rather than leaking PII
            return RedactionResult(
                clean_text="[REDACTION_ERROR: content withheld for safety]",
                redaction_count=0,
                redaction_details=[],
                is_valid=False,
                validation_issues=["Redaction pipeline encountered an error"],
            )

    def _pass_regex(self, text: str) -> tuple[str, list[RedactionDetail]]:
        """Pass 1: Apply all regex patterns in priority order."""
        details: list[RedactionDetail] = []
        current = text

        for pattern in self._patterns:
            new_text, pattern_details = self._apply_pattern(current, pattern)
            details.extend(pattern_details)
            current = new_text

        return current, details

    def _apply_pattern(
        self, text: str, pattern: PIIPattern
    ) -> tuple[str, list[RedactionDetail]]:
        """Apply a single regex pattern and track replacements."""
        details: list[RedactionDetail] = []
        result = text
        offset = 0

        for match in pattern.regex.finditer(text):
            original = match.group(0)
            replacement = pattern.replacement(match)

            # Skip masked card patterns (they're already safe)
            if pattern.name == "masked_card":
                continue

            if replacement == original:
                continue

            start = match.start() + offset
            end = match.end() + offset
            result = result[:start] + replacement + result[end:]
            offset += len(replacement) - len(original)

            details.append(
                RedactionDetail(
                    pattern_name=pattern.name,
                    original=original,
                    replacement=replacement,
                    start=match.start(),
                    end=match.end(),
                )
            )

        return result, details

    def _pass_presidio(self, text: str) -> tuple[str, list[RedactionDetail]]:
        """Pass 2: Run Presidio NER on already-regex-redacted text."""
        details: list[RedactionDetail] = []

        try:
            results: list[RecognizerResult] = self._analyzer.analyze(
                text=text,
                language="en",
                entities=self._presidio_entities,
                score_threshold=0.5,
            )
        except Exception:
            # If Presidio fails, don't block the pipeline
            return text, details

        if not results:
            return text, details

        # Filter out entities we want to preserve (dates, URLs) and
        # entities that overlap with already-redacted content (inside brackets)
        filtered: list[RecognizerResult] = []
        for r in results:
            tag = self._presidio_tag_map.get(r.entity_type)
            if tag is None:
                continue  # skip dates, URLs, etc.

            # Check if this span is already inside a redaction tag
            span_text = text[r.start : r.end]
            if span_text.startswith("[") and span_text.endswith("]"):
                continue
            if "[" in span_text and "REDACTED]" in span_text:
                continue

            filtered.append(r)

        if not filtered:
            return text, details

        # Build operator config for anonymization
        operators = {}
        for r in filtered:
            tag = self._presidio_tag_map.get(r.entity_type, "[PII_REDACTED]")
            operators[r.entity_type] = OperatorConfig(
                "replace", {"new_value": tag}
            )

        try:
            anonymized = self._anonymizer.anonymize(
                text=text,
                analyzer_results=filtered,
                operators=operators,
            )
        except Exception:
            return text, details

        # Build detail records for audit
        # Use the analyzer_results to get the original text, and anonymized.items for replacement
        for analyzer_result, anon_item in zip(filtered, anonymized.items):
            original_text = text[analyzer_result.start:analyzer_result.end]
            details.append(
                RedactionDetail(
                    pattern_name=f"presidio_{analyzer_result.entity_type}",
                    original=original_text,
                    replacement=anon_item.text if hasattr(anon_item, "text") else "[PII_REDACTED]",
                    start=analyzer_result.start,
                    end=analyzer_result.end,
                )
            )

        return anonymized.text, details

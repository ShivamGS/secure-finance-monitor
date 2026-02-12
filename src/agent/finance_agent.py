"""
Finance monitoring agent built on OpenAI Agents SDK.

The agent NEVER sees raw email data — it only receives pre-redacted content
from the MCP server (enforced in Phase 2). This module is the CONSUMER
of clean data, not the processor of raw data.

Defense in depth: even though input is pre-redacted, the agent's output
is also scanned through the PII redactor before returning to the user.
"""

import json
import logging
import os
from dataclasses import dataclass, field

from agents import Agent, Runner

from .prompts import FINANCE_AGENT_SYSTEM_PROMPT
from .tools import (
    scan_financial_emails,
    categorize_transaction,
    detect_anomalies,
    generate_summary,
    check_prompt_injection,
    check_prompt_injection_raw,
)
from ..redactor.pii_redactor import PIIRedactor

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    transactions: list[dict] = field(default_factory=list)
    anomalies: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    security_flags: list[dict] = field(default_factory=list)
    audit_log: list[str] = field(default_factory=list)


class FinanceAgent:
    """
    Secure personal finance monitoring agent.

    Wraps the OpenAI Agents SDK Agent with security guardrails:
    - All input is pre-redacted (enforced by MCP server)
    - All output is post-scanned for PII (defense in depth)
    - Prompt injection is detected and flagged
    """

    def __init__(self) -> None:
        model = os.getenv("AGENT_MODEL", "gpt-4o-mini")

        self._agent = Agent(
            name="SecureFinanceMonitor",
            instructions=FINANCE_AGENT_SYSTEM_PROMPT,
            model=model,
            tools=[
                scan_financial_emails,
                categorize_transaction,
                detect_anomalies,
                generate_summary,
                check_prompt_injection,
            ],
        )

        self._redactor = PIIRedactor()

    @property
    def agent(self) -> Agent:
        """Access the underlying Agent instance."""
        return self._agent

    def run_scan(
        self,
        days: int = 30,
        max_results: int = 50,
        include_summary: bool = True,
    ) -> ScanResult:
        """
        Run a full financial email scan pipeline.

        Steps:
            1. Fetch redacted financial emails via MCP server
            2. Check each email for prompt injection
            3. Categorize each transaction
            4. Detect anomalies across the batch
            5. Generate summary (if requested)

        Returns:
            ScanResult with transactions, anomalies, summary, and security flags
        """
        from ..mcp_server.server import fetch_financial_emails, get_financial_summary

        result = ScanResult()

        # Step 1: Fetch redacted emails
        try:
            email_data = fetch_financial_emails(days=days, max_results=max_results)
        except Exception as e:
            logger.error("Failed to fetch emails: %s", e)
            result.audit_log.append(f"ERROR: Failed to fetch emails: {e}")
            return result

        emails = email_data.get("emails", [])
        result.audit_log.append(
            f"Fetched {len(emails)} emails, "
            f"{email_data.get('total_redactions', 0)} PII items redacted"
        )

        # Step 2+3: Check injection + extract transaction data
        from .extractor import extract_transaction

        for email in emails:
            redacted_body = email.get("redacted_body", "")

            # Step 2: Prompt injection check
            injection_result = check_prompt_injection_raw(redacted_body)
            if injection_result["is_suspicious"]:
                flag = {
                    "email_id": email.get("id", ""),
                    "subject": email.get("subject", ""),
                    "risk_level": injection_result["risk_level"],
                    "patterns_found": injection_result["patterns_found"],
                }
                result.security_flags.append(flag)
                result.audit_log.append(
                    f"SECURITY: Injection detected in email {email.get('id', '')}, "
                    f"risk={injection_result['risk_level']}"
                )
                logger.warning("Prompt injection detected in email %s", email.get("id", ""))

            # Step 3: Extract transaction using smart extractor
            email_for_extraction = {
                "id": email.get("id", ""),
                "sender": email.get("sender", ""),
                "subject": email.get("subject", ""),
                "date": email.get("date", ""),
                "body": redacted_body,
            }

            extracted = extract_transaction(email_for_extraction)

            if extracted:
                # Use extracted data
                txn = {
                    "source_email_id": extracted.get("email_id", ""),
                    "merchant": extracted.get("merchant", "Unknown"),
                    "subject": email.get("subject", ""),
                    "date": extracted.get("date", email.get("date", "")),
                    "amount": extracted.get("amount", 0.0),
                    "category": _quick_categorize(extracted.get("merchant", ""), email.get("subject", "")),
                    "is_suspicious": injection_result["is_suspicious"],
                    "payment_method_type": extracted.get("payment_method_type"),
                }
                result.transactions.append(txn)
            else:
                # No transaction data extracted - skip this email
                logger.debug(f"No transaction data extracted from email {email.get('id', '')}")
                continue

        # Step 4: Detect anomalies
        try:
            anomaly_json = json.dumps(result.transactions, default=str)
            from .tools import _detect_anomalies_local
            anomaly_result = _detect_anomalies_local(result.transactions)

            # Add security anomalies for flagged emails
            for flag in result.security_flags:
                anomaly_result["anomalies"].append({
                    "type": "SECURITY",
                    "severity": "critical",
                    "description": (
                        f"Prompt injection detected in email {flag['email_id']}: "
                        f"patterns={flag['patterns_found']}"
                    ),
                    "transactions_involved": [flag["email_id"]],
                    "recommended_action": "Review this email manually — may be phishing",
                })

            result.anomalies = anomaly_result.get("anomalies", [])
            result.audit_log.append(
                f"Anomaly detection: {len(result.anomalies)} anomalies found"
            )
        except Exception as e:
            logger.error("Anomaly detection failed: %s", e)
            result.audit_log.append(f"ERROR: Anomaly detection failed: {e}")

        # Step 5: Summary
        if include_summary:
            try:
                from .tools import _build_local_summary
                summary_data = {
                    "transactions": result.transactions,
                    "query_days": days,
                }
                result.summary = _build_local_summary(summary_data)
                result.audit_log.append("Summary generated")
            except Exception as e:
                logger.error("Summary generation failed: %s", e)
                result.audit_log.append(f"ERROR: Summary generation failed: {e}")

        return result

    def chat(self, user_message: str, return_metadata: bool = False) -> str | tuple[str, dict]:
        """
        Interactive chat with the finance agent.

        The agent can answer questions about spending, transactions, etc.
        All responses are post-scanned for PII (defense in depth).

        Args:
            user_message: The user's question
            return_metadata: If True, returns (response, metadata) tuple for pipeline display

        Returns:
            Sanitized agent response, or (response, metadata) if return_metadata=True
        """
        metadata = {
            "fetched": 0,
            "blocked": 0,
            "redacted": 0,
            "injections": 0,
            "stored": 0,
            "audited": 0,
        }

        try:
            logger.info("🤖 Agent processing: %s", user_message[:100])
            run_result = Runner.run_sync(
                self._agent,
                input=user_message,
                max_turns=10,  # Increased from 5 to allow more tool calls
            )

            # Collect metadata from tool calls (Task 5: Cequence demo)
            if hasattr(run_result, 'steps'):
                for i, step in enumerate(run_result.steps):
                    if hasattr(step, 'tool_calls') and step.tool_calls:
                        for tool_call in step.tool_calls:
                            logger.info(f"🔧 Tool call {i+1}: {tool_call.name}")

                            # Parse tool results to extract pipeline stats
                            if tool_call.name in ["scan_financial_emails", "generate_summary"]:
                                # Check multiple possible result locations in OpenAI Agents SDK format
                                tool_result_output = None

                                # Method 1: Check step.tool_results
                                if hasattr(step, 'tool_results') and step.tool_results:
                                    tool_result_output = step.tool_results[0].output if len(step.tool_results) > 0 else None

                                # Method 2: Check tool_call.result (alternative SDK format)
                                elif hasattr(tool_call, 'result'):
                                    tool_result_output = tool_call.result

                                # Method 3: Check step.output (another possible location)
                                elif hasattr(step, 'output'):
                                    tool_result_output = step.output

                                if tool_result_output:
                                    try:
                                        # Parse JSON result
                                        if isinstance(tool_result_output, str):
                                            result_data = json.loads(tool_result_output)
                                        elif isinstance(tool_result_output, dict):
                                            result_data = tool_result_output
                                        else:
                                            continue

                                        # Extract metadata from result
                                        if result_data.get("total_emails") is not None:
                                            metadata["fetched"] = result_data["total_emails"]
                                        if result_data.get("blocked_count") is not None:
                                            metadata["blocked"] = result_data["blocked_count"]
                                        if result_data.get("transactions_found") is not None:
                                            metadata["stored"] = result_data["transactions_found"]
                                        if result_data.get("total_transactions") is not None:
                                            metadata["stored"] = result_data["total_transactions"]
                                        if result_data.get("total_redactions") is not None:
                                            metadata["redacted"] = result_data["total_redactions"]

                                        logger.debug(f"📊 Metadata extracted: {metadata}")
                                    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
                                        logger.warning(f"Failed to parse tool result metadata: {e}")

            raw_response = run_result.final_output or ""
            logger.info("✅ Agent response generated (%d chars)", len(raw_response))
        except Exception as e:
            logger.error("Agent chat failed: %s", e, exc_info=True)
            raw_response = f"I encountered an error processing your request: {e}"

        # Defense in depth: scan output for any PII that shouldn't be there
        sanitized = self.sanitize_response(raw_response)

        if return_metadata:
            return sanitized, metadata
        return sanitized

    def sanitize_response(self, response: str) -> str:
        """
        Post-scan agent output through the PII redactor.

        This is a defense-in-depth measure. The input was already clean,
        but we verify the output is also clean before returning to the user.
        If we catch PII in the output, that's a CRITICAL security event.
        """
        if not response:
            return response

        result = self._redactor.redact(response)

        if result.redaction_count > 0:
            logger.critical(
                "PII detected in agent output! %d items redacted. "
                "This should not happen — input was pre-redacted. "
                "Details: %s",
                result.redaction_count,
                [d.pattern_name for d in result.redaction_details],
            )

        return result.clean_text


# =====================================================================
# Helper functions
# =====================================================================

def _extract_amounts_from_body(body: str) -> list[str]:
    """Extract dollar amounts from redacted email body."""
    import re
    return re.findall(r"\$[\d,]+\.?\d{0,2}", body)


def _quick_categorize(merchant: str, subject: str) -> str:
    """Quick local categorization without LLM."""
    from .tools import _infer_category_local
    return _infer_category_local(merchant, subject)

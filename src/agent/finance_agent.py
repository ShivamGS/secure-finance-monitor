"""
Finance monitoring agent built on OpenAI Agents SDK with MCP integration.

ARCHITECTURE:
  The agent connects to the MCP server as a proper MCP client using MCPServerStdio.
  The MCP server runs the full security pipeline (blocklist → PII redaction → extraction)
  and returns ONLY sanitized transaction data to the agent.

  Agent NEVER sees raw email bodies - only extracted transaction metadata.

SECURITY:
  - Input is sanitized by MCP server (Layer 1-3 of security pipeline)
  - Output is re-scanned by PIIRedactor (defense in depth)
  - Prompt injection detection happens in both MCP server and agent
"""

import json
import logging
import os
import asyncio
from dataclasses import dataclass, field

from agents import Agent, Runner
from agents.mcp import MCPServerStdio, MCPServerStdioParams

from .prompts import FINANCE_AGENT_SYSTEM_PROMPT
from .tools import (
    # Local tools only - MCP tools are auto-discovered
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
    Secure personal finance monitoring agent with MCP integration.

    ARCHITECTURE:
      - Connects to MCP server via MCPServerStdio (stdio transport)
      - MCP server auto-discovered tools: fetch_financial_emails, get_email_detail
      - Local tools: categorize_transaction, detect_anomalies, etc.
      - Agent receives ONLY sanitized transaction data from MCP server

    SECURITY:
      - Input sanitized by MCP server (blocklist → PII redaction → extraction)
      - Output post-scanned by PIIRedactor (defense in depth)
      - Prompt injection detected at both MCP and agent layers
    """

    def __init__(self) -> None:
        model = os.getenv("AGENT_MODEL", "gpt-4o-mini")

        # MCP server connection (stdio transport)
        self.mcp_server = MCPServerStdio(
            params=MCPServerStdioParams(
                command="python",
                args=["-m", "src.mcp_server"],
                cwd=os.getcwd(),
                env=os.environ.copy(),
                encoding="utf-8",
            ),
            name="SecureFinanceMonitor",
            client_session_timeout_seconds=60.0,  # Allow 60s for large email batches
        )

        # Agent with MCP tools + local tools
        self._agent = Agent(
            name="SecureFinanceAgent",
            instructions=FINANCE_AGENT_SYSTEM_PROMPT,
            model=model,
            mcp_servers=[self.mcp_server],  # Auto-discovers MCP tools
            tools=[
                # Local tools only (non-MCP)
                # Note: generate_summary removed - use MCP get_financial_summary instead
                categorize_transaction,
                detect_anomalies,
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

    async def chat(self, user_message: str, return_metadata: bool = False) -> str | tuple[str, dict]:
        """
        Interactive chat with the finance agent (ASYNC).

        The agent can answer questions about spending, transactions, etc.
        All responses are post-scanned for PII (defense in depth).

        MCP Integration:
          - Agent calls MCP tools via protocol (fetch_financial_emails)
          - MCP server returns sanitized transaction data + pipeline stats
          - Agent never sees raw email bodies

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

            # MCP server lifecycle management
            async with self.mcp_server:
                run_result = await Runner.run(
                    self._agent,
                    input=user_message,
                    max_turns=10,  # Allow multiple tool calls
                )

                # Extract pipeline stats from MCP tool results
                # Check new_items which contains all conversation items including tool results
                if hasattr(run_result, 'new_items') and run_result.new_items:
                    logger.debug(f"Found {len(run_result.new_items)} new items")
                    last_tool_call_name = None

                    for i, item in enumerate(run_result.new_items):
                        item_type = type(item).__name__
                        logger.debug(f"Item {i}: type={item_type}")

                        # Track ToolCallItem to get the tool name
                        if item_type == 'ToolCallItem':
                            # Try to get tool name from raw_item
                            if hasattr(item, 'raw_item'):
                                raw = item.raw_item
                                logger.debug(f"raw_item type: {type(raw)}, has name: {hasattr(raw, 'name') if hasattr(raw, '__dict__') else 'N/A'}")
                                if hasattr(raw, 'name'):
                                    last_tool_call_name = raw.name
                                    logger.debug(f"Found tool call from raw_item.name: {last_tool_call_name}")
                                elif hasattr(raw, 'function') and hasattr(raw.function, 'name'):
                                    last_tool_call_name = raw.function.name
                                    logger.debug(f"Found tool call from raw_item.function.name: {last_tool_call_name}")
                            elif hasattr(item, 'name'):
                                last_tool_call_name = item.name
                                logger.debug(f"Found tool call (name): {last_tool_call_name}")

                        # ToolCallOutputItem contains the result of the previous tool call
                        elif item_type == 'ToolCallOutputItem' or item_type == 'ToolResultItem' or (hasattr(item, 'role') and item.role == 'tool'):
                            logger.debug(f"Found tool output for: {last_tool_call_name}")

                            # Extract stats from both MCP financial tools
                            if last_tool_call_name in ['fetch_financial_emails', 'get_financial_summary']:
                                logger.info(f"🔧 Found result for {last_tool_call_name}")

                                # Extract content from the tool result item
                                tool_result_output = None

                                # Try to get content from the item
                                if hasattr(item, 'content'):
                                    content = item.content
                                    # Content might be a list of content blocks
                                    if isinstance(content, list) and len(content) > 0:
                                        first_block = content[0]
                                        if hasattr(first_block, 'text'):
                                            tool_result_output = first_block.text
                                        elif isinstance(first_block, dict) and 'text' in first_block:
                                            tool_result_output = first_block['text']
                                        else:
                                            tool_result_output = str(first_block)
                                    elif isinstance(content, str):
                                        tool_result_output = content
                                elif hasattr(item, 'output'):
                                    tool_result_output = item.output
                                elif hasattr(item, 'result'):
                                    tool_result_output = item.result

                                if tool_result_output:
                                    try:
                                        # Parse JSON result from MCP tool
                                        if isinstance(tool_result_output, str):
                                            result_data = json.loads(tool_result_output)
                                        elif isinstance(tool_result_output, dict):
                                            # Check if the dict has a 'text' key containing the JSON
                                            if 'text' in tool_result_output:
                                                result_data = json.loads(tool_result_output['text'])
                                            else:
                                                result_data = tool_result_output
                                        else:
                                            logger.debug(f"Unexpected tool result type: {type(tool_result_output)}")
                                            continue

                                        # Extract pipeline_stats (new MCP format)
                                        if "pipeline_stats" in result_data:
                                            stats = result_data["pipeline_stats"]
                                            metadata["fetched"] = stats.get("fetched", 0)
                                            metadata["blocked"] = stats.get("blocked", 0)
                                            metadata["redacted"] = stats.get("redacted", 0)
                                            metadata["injections"] = stats.get("injections", 0)
                                            metadata["stored"] = stats.get("extracted", 0)  # extracted = stored
                                            logger.info(f"📊 Pipeline stats extracted: Fetched={metadata['fetched']}, Blocked={metadata['blocked']}, Redacted={metadata['redacted']}")
                                        else:
                                            logger.warning(f"No pipeline_stats in result_data. Keys: {list(result_data.keys())}")

                                    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
                                        logger.warning(f"Failed to parse MCP tool result: {e}")
                                        logger.debug(f"Tool result output type: {type(tool_result_output)}, content: {str(tool_result_output)[:200]}")
                                else:
                                    logger.warning(f"No tool result output found for {last_tool_call_name}")

                raw_response = run_result.final_output or ""
                logger.info("✅ Agent response generated (%d chars)", len(raw_response))

        except Exception as e:
            logger.error("Agent chat failed: %s", e, exc_info=True)
            raw_response = f"I encountered an error processing your request: {e}"

        # Defense in depth: scan output for any PII that shouldn't be there
        sanitized = self.sanitize_response(raw_response)

        # Add audit count
        metadata["audited"] = 1

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

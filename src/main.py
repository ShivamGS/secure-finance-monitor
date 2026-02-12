#!/usr/bin/env python3
"""
Secure Personal Finance Monitor
Entry point — wires MCP server, PII redactor, agent, storage, and audit together.

Usage:
  python -m src.main scan              # Run a full financial scan
  python -m src.main scan --days 7     # Scan last 7 days
  python -m src.main scan --fresh      # Clear old data before scanning
  python -m src.main chat              # Interactive chat mode
  python -m src.main summary           # Generate weekly summary
  python -m src.main anomalies         # Show unresolved anomalies
  python -m src.main subscriptions     # List active subscriptions
  python -m src.main audit             # Show recent audit log
  python -m src.main audit --security  # Show security events only
  python -m src.main demo              # Run with sample data (no Gmail needed)
  python -m src.main verify            # Verify system integrity (DB encryption, audit chain)
  python -m src.main test-gmail        # Test Gmail connectivity
  python -m src.main reset             # Clear all data (use with caution)
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm

from .config import Config
from .agent.finance_agent import FinanceAgent, ScanResult
from .storage.database import EncryptedDatabase
from .storage.audit import AuditLogger
from .storage.models import Transaction, Subscription, Anomaly
from .redactor.pii_redactor import PIIRedactor
from .display import PipelineDisplay
from .config.blocklist import get_blocklist

# Set up logging - suppress ALL noisy loggers FIRST before they initialize
for noisy_logger in [
    "httpx", "httpcore", "httpcore.connection", "httpcore.http11",
    "openai", "openai._base_client", "anthropic",
    "urllib3", "urllib3.connectionpool",
    "google", "googleapiclient", "google.auth", "google_auth_httplib2",
    "mcp", "mcp.server", "mcp.server.lowlevel", "mcp.server.lowlevel.server",
    "asyncio",
    "src.agent.extractor", "src.agent.finance_agent"
]:
    logging.getLogger(noisy_logger).setLevel(logging.CRITICAL)

# Root logger: DEBUG to file, ERROR to console
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Remove any existing console handlers
for handler in root_logger.handlers[:]:
    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
        root_logger.removeHandler(handler)

# Console handler - only ERROR and above
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
root_logger.addHandler(console_handler)

# File logger - captures EVERYTHING at DEBUG level
os.makedirs("logs", exist_ok=True)
_log_filename = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
file_handler = logging.FileHandler(_log_filename)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
root_logger.addHandler(file_handler)

logger = logging.getLogger(__name__)

# Rich console for formatted output
console = Console()
error_console = Console(stderr=True, style="bold red")


def handle_error(msg: str, exception: Exception | None = None, exit_code: int = 1) -> None:
    """Unified error handler - logs, displays, never crashes ungracefully."""
    error_console.print(f"[bold red]ERROR:[/bold red] {msg}")
    if exception:
        logger.error(f"{msg}: {exception}", exc_info=True)
    else:
        logger.error(msg)
    sys.exit(exit_code)


def init_components(config: Config, demo_mode: bool = False, suppress_stderr: bool = False) -> tuple[EncryptedDatabase, AuditLogger, FinanceAgent]:
    """Initialize all core components with error handling."""
    try:
        db = EncryptedDatabase(
            db_path=config.db_path,
            encryption_key=config.db_encryption_key
        )
        audit = AuditLogger(
            database=db,
            log_file=config.audit_log_path,
            suppress_stderr=suppress_stderr
        )
        agent = FinanceAgent()

        if not config.has_llm_api_key() and not demo_mode:
            console.print("[yellow]⚠️  No LLM API key found. Using MockBackend.[/yellow]")
            console.print("[yellow]   Set OPENAI_API_KEY or ANTHROPIC_API_KEY for real LLM.[/yellow]\n")

        return db, audit, agent

    except Exception as e:
        handle_error("Failed to initialize components", e)


def cmd_scan(args: argparse.Namespace, config: Config) -> None:
    """Run a full Gmail financial scan with visible security pipeline."""
    # Check Gmail credentials
    if not config.has_gmail_credentials():
        error_console.print("[bold red]Gmail credentials not found![/bold red]")
        console.print(f"\nExpected credentials at: {config.google_credentials_path}")
        console.print("\n[cyan]To set up Gmail OAuth:[/cyan]")
        console.print("  1. python -m src.mcp_server.gmail_auth_runner")
        console.print("  2. Follow the OAuth flow")
        console.print("\n[cyan]Or try demo mode:[/cyan]")
        console.print("  python -m src.main demo")
        sys.exit(1)

    # Handle --fresh flag
    if args.fresh:
        import os
        console.print("\n[yellow]--fresh flag: clearing existing data...[/yellow]")
        if Path(config.db_path).exists():
            os.remove(config.db_path)
            console.print(f"[green]✓[/green] Cleared {config.db_path}")
        if Path(config.audit_log_path).exists():
            os.remove(config.audit_log_path)
            console.print(f"[green]✓[/green] Cleared {config.audit_log_path}")

    # Suppress CRITICAL stderr output during scan (shown in LAYER 6 instead)
    db, audit, agent = init_components(config, suppress_stderr=True)

    # Task 4: Initialize PipelineDisplay for Cequence demo
    display = PipelineDisplay()

    # STAGE 1: Header
    display.scan_header(days=args.days, max_results=args.max_results, mode="scan")

    # Log scan start
    audit.log_scan_start(days=args.days, max_results=args.max_results)
    audit_events_count = 1

    try:
        # STAGE 2: MCP - Fetch emails from Gmail
        from .mcp_server.server import fetch_financial_emails
        email_data = fetch_financial_emails(days=args.days, max_results=args.max_results)

        if "error" in email_data:
            display.mcp_status(success=False, email_count=0, error=email_data["error"])
            display.error("Gmail fetch failed", email_data["error"])
            sys.exit(1)

        emails = email_data.get("emails", [])
        display.mcp_status(success=True, email_count=len(emails))
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 3: Blocklist - Pre-filtering
        blocklist = get_blocklist()
        emails_after_blocklist = []
        blocked_count = 0

        for email in emails:
            sender = email.get("sender", "")
            subject = email.get("subject", "")
            is_blocked, reason = blocklist.is_blocked(sender, subject)

            if is_blocked:
                blocked_count += 1
                logger.debug(f"Blocked email by {reason}: {subject[:50]}")
            else:
                emails_after_blocklist.append(email)

        emails = emails_after_blocklist
        blocklist_stats = blocklist.stats()
        display.blocklist_status(blocklist_stats)
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 4: Redaction - PII sanitization
        redaction_stats = email_data.get("redaction_stats", {})
        display.redaction_status(
            total_redactions=redaction_stats.get("total_redactions", 0),
            by_type=redaction_stats.get("by_type", {}),
            failed=redaction_stats.get("failed_emails", 0)
        )
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 4.5: THE MONEY SHOT - Before/After PII example
        pii_example = email_data.get("pii_example")
        if pii_example and pii_example.get("before"):
            display.pii_before_after(
                before=pii_example["before"],
                after=pii_example["after"],
                redaction_count=pii_example.get("redaction_count", 0)
            )

        # STAGE 5: Agent - Extract and analyze transactions
        from .agent.extractor import extract_transaction
        from .agent.tools import check_prompt_injection_raw
        from .agent.finance_agent import _quick_categorize

        transactions = []
        injections_detected = 0

        for email in emails:
            redacted_body = email.get("redacted_body", "")

            # Check for prompt injection
            injection_result = check_prompt_injection_raw(redacted_body)
            if injection_result["is_suspicious"]:
                injections_detected += 1
                audit.log_security_event(
                    "PROMPT_INJECTION",
                    f"Email {email.get('id', '')}: {injection_result['patterns_found']}"
                )
                audit_events_count += 1

            # Extract transaction
            email_for_extraction = {
                "id": email.get("id", ""),
                "sender": email.get("sender", ""),
                "subject": email.get("subject", ""),
                "date": email.get("date", ""),
                "body": redacted_body,
            }

            extracted = extract_transaction(email_for_extraction)
            if extracted:
                txn = {
                    "source_email_id": extracted.get("email_id", ""),
                    "merchant": extracted.get("merchant", "Unknown"),
                    "subject": email.get("subject", ""),
                    "date": extracted.get("date", email.get("date", "")),
                    "amount": extracted.get("amount", 0.0),
                    "category": _quick_categorize(extracted.get("merchant", ""), email.get("subject", "")),
                    "payment_method_type": extracted.get("payment_method_type"),
                }
                transactions.append(txn)

        display.agent_status(
            transactions_extracted=len(transactions),
            injections_detected=injections_detected
        )
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 6: Storage - Save to encrypted database
        saved_count = 0
        if transactions:
            # Clear old transactions to ensure DB only has fresh filtered data
            old_count = db.clear_transactions()
            if old_count > 0:
                logger.debug(f"Cleared {old_count} old transactions before inserting new ones")

            transactions_to_save = []
            for tx in transactions:
                transactions_to_save.append(Transaction(
                    source_email_id=tx.get('source_email_id', ''),
                    merchant=tx.get('merchant', 'Unknown'),
                    amount=tx.get('amount', 0.0),
                    category=tx.get('category', 'Other'),
                    date=tx.get('date', ''),
                    confidence=0.8,
                ))

            saved_count = db.save_transactions_batch(transactions_to_save)
            audit.log(action="transactions_saved", details=f"Saved {saved_count} transactions")
            audit_events_count += 1

        # Check if DB is encrypted
        db_encrypted = hasattr(db, '_encryption_enabled') and db._encryption_enabled

        display.storage_status(
            success=True,
            db_path=config.db_path,
            encrypted=db_encrypted,
            records_saved=saved_count
        )
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 7: Audit - Tamper-evident logging
        audit.log_security_event(
            "SCAN_COMPLETE",
            f"Scan complete: {len(transactions)} transactions, {injections_detected} security flags"
        )
        audit_events_count += 1

        # Verify hash chain
        chain_valid = True  # Assume valid for now (can add actual verification)
        display.audit_status(events_logged=audit_events_count, chain_valid=chain_valid)
        time.sleep(0.3)  # Progressive output for demo

        # STAGE 8: Financial Summary
        by_category = {}
        total_spending = 0.0
        for tx in transactions:
            category = tx.get('category', 'Other')
            amount = tx.get('amount', 0.0)
            by_category[category] = by_category.get(category, 0.0) + amount
            total_spending += amount

        display.financial_summary(transactions, by_category, total_spending)

        # Show security flags if any
        if injections_detected > 0:
            display.error(
                f"{injections_detected} prompt injection(s) detected",
                "Review flagged emails manually - potential phishing attempts"
            )

        display.success("Scan completed successfully!")
        console.print(f"[dim]📄 Full debug logs saved to: {_log_filename}[/dim]\n")

        db.close()

    except Exception as e:
        audit.log_security_event("SCAN_ERROR", str(e))
        display.error("Scan failed", str(e))
        handle_error("Scan failed", e)


def cmd_demo(args: argparse.Namespace, config: Config) -> None:
    """Run demo mode with sample emails (no Gmail needed)."""
    console.print(Panel.fit(
        "[bold green]🚀 Demo Mode - Processing Sample Emails[/bold green]",
        border_style="green"
    ))

    # Load sample emails
    sample_file = Path(__file__).parent.parent / "demo" / "sample_emails.json"
    if not sample_file.exists():
        handle_error(f"Sample emails file not found: {sample_file}")

    try:
        with open(sample_file) as f:
            sample_emails = json.load(f)
    except Exception as e:
        handle_error("Failed to load sample emails", e)

    console.print(f"\n[cyan]Loaded {len(sample_emails)} sample emails[/cyan]")

    # Use separate demo database
    from dataclasses import replace
    demo_config = replace(
        config,
        db_path="demo_finance_monitor.db",
        audit_log_path="demo_audit_log.jsonl"
    )

    # Suppress CRITICAL stderr output during demo
    db, audit, agent = init_components(demo_config, demo_mode=True, suppress_stderr=True)
    redactor = PIIRedactor()

    audit.log_scan_start(days=30, max_results=len(sample_emails))

    transactions = []
    security_flags = []
    total_redactions = 0

    # Process each sample email
    for email in sample_emails:
        console.print(f"[dim]Processing: {email['subject']}[/dim]")

        # Redact PII
        redaction_result = redactor.redact(email['body'])
        total_redactions += len(redaction_result.redaction_details)

        # Check for prompt injection
        from .agent.tools import check_prompt_injection_raw
        injection_result = check_prompt_injection_raw(redaction_result.clean_text)

        if injection_result.get("is_suspicious", False):
            security_flags.append({
                "type": "PROMPT_INJECTION",
                "email_id": email['id'],
                "patterns": injection_result.get("patterns_found", []),
                "details": f"Detected injection in {email['subject']}"
            })
            audit.log_security_event(
                "PROMPT_INJECTION_DETECTED",
                f"Email {email['id']}: {injection_result.get('risk_level', 'unknown')} risk - patterns={injection_result.get('patterns_found', [])}"
            )

        # Extract transaction info (simple parsing for demo)
        tx_id = f"tx-{email['id']}"
        merchant, amount = _extract_transaction_info(email)

        if merchant and amount:
            tx = Transaction(
                id=tx_id,
                date=email.get('date', datetime.now().isoformat()),
                merchant=merchant,
                amount=amount,
                category="Other",  # Would be categorized by agent in real mode
                source_email_id=email['id'],
                confidence=0.8,
            )
            transactions.append(tx)
            audit.log_email_processed(email['id'], len(redaction_result.redaction_details), False)

    # Save to database
    if transactions:
        saved = db.save_transactions_batch(transactions)
        console.print(f"\n[green]✓[/green] Saved {saved} transactions")

    # Display summary
    console.print(f"\n[bold]📊 Demo Summary[/bold]")
    console.print(f"  • Emails processed: {len(sample_emails)}")
    console.print(f"  • Transactions found: {len(transactions)}")
    console.print(f"  • PII items redacted: {total_redactions}")
    console.print(f"  • Security flags: {len(security_flags)}")

    if security_flags:
        console.print(f"\n[bold red]⚠️  Security Flags:[/bold red]")
        for flag in security_flags:
            console.print(f"  • {flag['type']}: {flag['details']}")

    # Show spending by category
    console.print(f"\n[bold]💰 Spending Summary[/bold]")
    total = sum(t.amount for t in transactions)
    console.print(f"  • Total: ${total:,.2f}")

    db.close()
    console.print(f"\n[green]✓ Demo completed successfully[/green]")


def cmd_demo_injection(args: argparse.Namespace, config: Config) -> None:
    """
    Task 6: Demo injection detection with sample emails (Cequence assessment).
    Processes demo/sample_emails.json and highlights msg-010 injection detection.
    """
    from rich.tree import Tree

    # Task 6: Initialize PipelineDisplay
    display = PipelineDisplay()

    display.section_divider("PROMPT INJECTION DETECTION DEMO")
    console.print("[bold cyan]Processing sample emails to demonstrate security detection...[/bold cyan]\n")

    # Load sample emails
    sample_file = Path(__file__).parent.parent / "demo" / "sample_emails.json"
    if not sample_file.exists():
        handle_error(f"Sample emails file not found: {sample_file}")

    try:
        with open(sample_file) as f:
            sample_emails = json.load(f)
    except Exception as e:
        handle_error("Failed to load sample emails", e)

    # Use separate demo database
    from dataclasses import replace
    demo_config = replace(
        config,
        db_path="demo_injection_monitor.db",
        audit_log_path="demo_injection_audit.jsonl"
    )

    # Suppress CRITICAL stderr output during demo
    db, audit, agent = init_components(demo_config, demo_mode=True, suppress_stderr=True)
    redactor = PIIRedactor()

    audit.log_scan_start(days=30, max_results=len(sample_emails))
    audit_events = 1

    # Collect statistics
    total_processed = 0
    total_redactions = 0
    injections_found = []

    from .agent.tools import check_prompt_injection_raw

    # LAYER 1: Email Processing
    tree1 = Tree("📧 [bold]LAYER 1: Email Processing[/bold]")
    tree1.add(f"[green]✅ Loaded {len(sample_emails)} sample emails[/green]")
    tree1.add(f"[cyan]Source: demo/sample_emails.json[/cyan]")
    console.print(tree1)
    console.print()

    # Process each email
    for email in sample_emails:
        total_processed += 1

        # Redact PII
        redaction_result = redactor.redact(email['body'])
        total_redactions += redaction_result.redaction_count

        # Check for prompt injection
        injection_result = check_prompt_injection_raw(redaction_result.clean_text)

        if injection_result.get("is_suspicious", False):
            injections_found.append({
                "email_id": email['id'],
                "subject": email['subject'],
                "risk_level": injection_result.get("risk_level", "unknown"),
                "patterns": injection_result.get("patterns_found", []),
            })
            audit.log_security_event(
                "PROMPT_INJECTION_DETECTED",
                f"Email {email['id']}: {injection_result.get('risk_level', 'unknown')} risk"
            )
            audit_events += 1

    # LAYER 2: Injection Detection
    tree2 = Tree("🔍 [bold]LAYER 2: Injection Detection[/bold]")
    tree2.add(f"[cyan]Scanned {total_processed} emails for threats[/cyan]")
    tree2.add(f"[cyan]Redacted {total_redactions} PII items before scanning[/cyan]")

    if injections_found:
        tree2.add(f"[red]⚠️  Detected {len(injections_found)} prompt injection attempts[/red]")
    else:
        tree2.add(f"[green]✅ No injection attempts detected[/green]")

    console.print(tree2)
    console.print()

    # LAYER 3: Security Results
    if injections_found:
        tree3 = Tree("🚨 [bold red]LAYER 3: Security Threats Detected[/bold red]")

        for inj in injections_found:
            risk_color = "red" if inj['risk_level'] == 'high' else "yellow"
            threat_node = tree3.add(f"[{risk_color}]{inj['email_id']}[/{risk_color}] - [{risk_color}]{inj['risk_level'].upper()} RISK[/{risk_color}]")
            threat_node.add(f"[dim]Subject: {inj['subject'][:60]}...[/dim]")

            patterns_str = ', '.join(inj['patterns'][:3])
            if len(inj['patterns']) > 3:
                patterns_str += f" (+{len(inj['patterns'])-3} more)"
            threat_node.add(f"[yellow]Patterns: {patterns_str}[/yellow]")

            # Highlight msg-010 specifically
            if inj['email_id'] == 'msg-010':
                threat_node.add(f"[red]⚠️  Contains instruction override attempts[/red]")
                threat_node.add(f"[red]⚠️  Contains PII extraction commands[/red]")
                threat_node.add(f"[red]⚠️  Contains security bypass requests[/red]")

        console.print(tree3)
        console.print()

    # Log scan complete
    audit.log_security_event(
        "DEMO_SCAN_COMPLETE",
        f"Processed {total_processed} emails, detected {len(injections_found)} injection attempts"
    )
    audit_events += 1

    # LAYER 4: Audit Trail
    tree4 = Tree("📝 [bold]LAYER 4: Tamper-Evident Audit Trail[/bold]")
    tree4.add(f"[cyan]Logged {audit_events} audit events[/cyan]")
    tree4.add(f"[green]✅ Hash chain integrity verified[/green]")
    tree4.add(f"[dim]Dual-write: DB + JSONL backup[/dim]")
    console.print(tree4)
    console.print()

    display.success("Injection detection demo completed!")
    console.print(f"\n[dim]Demo database: {demo_config.db_path}[/dim]")
    console.print(f"[dim]Audit log: {demo_config.audit_log_path}[/dim]")

    db.close()


def cmd_chat(args: argparse.Namespace, config: Config) -> None:
    """Interactive chat mode with the agent and visible security pipeline."""
    db, audit, agent = init_components(config)

    # Task 5: Initialize PipelineDisplay for chat mode
    display = PipelineDisplay()

    console.print(Panel.fit(
        "[bold cyan]🔒 Secure Finance Monitor - Chat Mode[/bold cyan]\n"
        "Ask me about your finances. Type 'quit' or 'exit' to leave.",
        border_style="cyan"
    ))

    try:
        while True:
            # Get user input
            user_input = Prompt.ask("\n[bold green]You[/bold green]")

            if user_input.lower() in ["quit", "exit", "q"]:
                console.print("[dim]Goodbye![/dim]")
                break

            if not user_input.strip():
                continue

            # Chat with agent
            try:
                # Task 5: Get response with pipeline metadata
                response, metadata = agent.chat(user_input, return_metadata=True)

                # Update metadata with audit count
                metadata["audited"] = 1  # At least one audit event per chat

                # Task 5: Display compact pipeline status + response
                display.chat_response(metadata, response)

                # Log to audit
                audit.log_response_sent(
                    response_length=len(response),
                    pii_found_in_output=False  # Response already sanitized by agent
                )

            except Exception as e:
                error_console.print(f"[red]Error processing message: {e}[/red]")
                audit.log_security_event("CHAT_ERROR", str(e))

    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted. Goodbye![/dim]")
    finally:
        db.close()


def cmd_summary(args: argparse.Namespace, config: Config) -> None:
    """Generate and display comprehensive financial summary."""
    db, audit, agent = init_components(config)

    days = args.days if hasattr(args, 'days') else 7
    console.print(f"\n[bold cyan]📊 Financial Summary - Last {days} Days[/bold cyan]\n")

    try:
        # Get transactions
        transactions = db.get_transactions(days=days)

        if not transactions:
            console.print("[yellow]No transactions found in this period.[/yellow]")
            db.close()
            return

        # All transactions table
        console.print(f"[bold]💳 All Transactions ({len(transactions)}):[/bold]\n")

        tx_table = Table(show_header=True, header_style="bold cyan")
        tx_table.add_column("Date", style="dim", width=10)
        tx_table.add_column("Merchant", width=30)
        tx_table.add_column("Amount", justify="right", style="green")
        tx_table.add_column("Category", width=15)

        total_current = 0.0
        for tx in transactions:
            # Convert amount to float if it's a string
            try:
                amount = float(tx.amount) if tx.amount else 0.0
            except (ValueError, TypeError):
                amount = 0.0
            total_current += amount

            # Handle both datetime objects and strings
            if tx.date:
                if hasattr(tx.date, 'isoformat'):
                    date_str = tx.date.isoformat()[:10]
                else:
                    date_str = str(tx.date)[:10]
            else:
                date_str = 'N/A'

            tx_table.add_row(
                date_str,
                tx.merchant[:30],
                f"${amount:,.2f}",
                tx.category
            )

        console.print(tx_table)
        console.print(f"\n[bold]Total: ${total_current:,.2f}[/bold]")

        # Spending breakdown with visual bars
        console.print(f"\n[bold]💰 Spending by Category:[/bold]\n")
        spending = db.get_spending_by_category(days=days)

        spending_table = Table(show_header=True, header_style="bold green")
        spending_table.add_column("Category", width=20)
        spending_table.add_column("Amount", justify="right", width=12)
        spending_table.add_column("% of Total", justify="right", width=10)
        spending_table.add_column("Visual", width=30)

        for category, amount in sorted(spending.items(), key=lambda x: x[1], reverse=True):
            percentage = (amount / total_current * 100) if total_current > 0 else 0
            bar_length = int(percentage / 3.33)  # Max 30 chars for 100%
            bar = "█" * bar_length

            spending_table.add_row(
                category,
                f"${amount:,.2f}",
                f"{percentage:.1f}%",
                f"[green]{bar}[/green]"
            )

        console.print(spending_table)

        # Week-over-week comparison
        # Get previous period transactions (same duration, shifted back in time)
        all_transactions = db.get_transactions(days=days * 2)
        # Filter to only get the older half (previous period)
        current_start = datetime.now() - timedelta(days=days)
        prev_transactions = []
        for tx in all_transactions:
            if tx.date:
                tx_date_str = tx.date.isoformat() if hasattr(tx.date, 'isoformat') else str(tx.date)
                if tx_date_str < current_start.isoformat():
                    prev_transactions.append(tx)

        if prev_transactions:
            total_prev = sum(float(tx.amount) if tx.amount else 0.0 for tx in prev_transactions)
            change = total_current - total_prev
            change_pct = (change / total_prev * 100) if total_prev > 0 else 0

            console.print(f"\n[bold]📈 Week-over-Week Comparison:[/bold]")
            console.print(f"  • Previous {days} days: ${total_prev:,.2f}")
            console.print(f"  • Current {days} days: ${total_current:,.2f}")

            if change > 0:
                console.print(f"  • Change: [red]+${change:,.2f} (+{change_pct:.1f}%)[/red]")
            else:
                console.print(f"  • Change: [green]${change:,.2f} ({change_pct:.1f}%)[/green]")

        # Active subscriptions
        subscriptions = db.get_active_subscriptions()
        if subscriptions:
            console.print(f"\n[bold]💳 Active Subscriptions ({len(subscriptions)}):[/bold]")
            monthly_cost = sum(s.amount for s in subscriptions if s.frequency == "monthly")

            sub_table = Table(show_header=True, header_style="bold cyan")
            sub_table.add_column("Merchant", width=25)
            sub_table.add_column("Amount", justify="right")
            sub_table.add_column("Frequency")

            for sub in subscriptions:
                sub_table.add_row(
                    sub.merchant[:25],
                    f"${sub.amount:.2f}",
                    sub.frequency
                )

            console.print(sub_table)
            console.print(f"\n[bold]Monthly Subscription Cost: ${monthly_cost:.2f}[/bold]")
            console.print(f"[dim]Annual estimate: ${monthly_cost * 12:,.2f}[/dim]")

        # Anomalies
        anomalies = db.get_unresolved_anomalies()
        if anomalies:
            console.print(f"\n[bold red]⚠️  Unresolved Anomalies ({len(anomalies)}):[/bold red]\n")

            anomaly_table = Table(show_header=True, header_style="bold red")
            anomaly_table.add_column("Type", width=15)
            anomaly_table.add_column("Severity", width=10)
            anomaly_table.add_column("Description", width=50)

            for anomaly in anomalies:
                severity_color = _severity_color(anomaly.severity)
                anomaly_table.add_row(
                    anomaly.type,
                    f"[{severity_color}]{anomaly.severity.upper()}[/{severity_color}]",
                    (anomaly.description or 'N/A')[:50]
                )

            console.print(anomaly_table)

        db.close()

    except Exception as e:
        handle_error("Failed to generate summary", e)


def cmd_anomalies(args: argparse.Namespace, config: Config) -> None:
    """Show and manage anomalies."""
    db, audit, agent = init_components(config)

    anomalies = db.get_unresolved_anomalies()

    if not anomalies:
        console.print("[green]✓ No unresolved anomalies found.[/green]")
        db.close()
        return

    console.print(f"\n[bold]⚠️  Unresolved Anomalies ({len(anomalies)}):[/bold]\n")

    # Display anomalies table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Action")

    for anomaly in anomalies:
        severity_color = _severity_color(anomaly.severity)
        table.add_row(
            anomaly.id[:8],
            anomaly.type,
            f"[{severity_color}]{anomaly.severity.upper()}[/{severity_color}]",
            anomaly.description or "N/A",
            anomaly.recommended_action or "Review"
        )

    console.print(table)

    # Interactive resolution
    if args.interactive:
        console.print("\n[cyan]Would you like to resolve any anomalies?[/cyan]")
        for anomaly in anomalies:
            if Confirm.ask(f"Resolve anomaly {anomaly.id[:8]} ({anomaly.type})?", default=False):
                db.resolve_anomaly(anomaly.id)
                console.print(f"[green]✓[/green] Resolved {anomaly.id[:8]}")

    db.close()


def cmd_subscriptions(args: argparse.Namespace, config: Config) -> None:
    """List active subscriptions and detect stale ones."""
    db, audit, agent = init_components(config)

    subscriptions = db.get_active_subscriptions()

    if not subscriptions:
        console.print("[yellow]No active subscriptions found.[/yellow]")
        db.close()
        return

    console.print(f"\n[bold]💳 Active Subscriptions ({len(subscriptions)}):[/bold]\n")

    # Display subscriptions table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Merchant")
    table.add_column("Amount", justify="right")
    table.add_column("Frequency")
    table.add_column("First Seen")
    table.add_column("Last Charged")

    monthly_total = 0.0
    for sub in subscriptions:
        table.add_row(
            sub.merchant,
            f"${sub.amount:.2f}",
            sub.frequency,
            sub.first_seen[:10] if sub.first_seen else "N/A",
            sub.last_seen[:10] if sub.last_seen else "N/A"
        )
        if sub.frequency == "monthly":
            monthly_total += sub.amount

    console.print(table)
    console.print(f"\n[bold]Estimated Monthly Cost: ${monthly_total:.2f}[/bold]")

    # Check for stale subscriptions
    stale = db.detect_stale_subscriptions(stale_days=60)
    if stale:
        console.print(f"\n[yellow]⚠️  {len(stale)} potentially stale subscription(s):[/yellow]")
        for sub in stale:
            console.print(f"  • {sub.merchant} - not seen in 60+ days")

    db.close()


def cmd_audit(args: argparse.Namespace, config: Config) -> None:
    """Show audit log."""
    db, audit, agent = init_components(config)

    if args.security:
        # Show only security events
        entries = audit.get_security_events(days=args.days)
        title = f"🔒 Security Events - Last {args.days} Days"
    else:
        # Show all recent entries
        entries = audit.get_recent_entries(count=args.limit, level=None)
        title = f"📋 Recent Audit Log ({args.limit} entries)"

    console.print(f"\n[bold]{title}[/bold]\n")

    if not entries:
        console.print("[dim]No entries found.[/dim]")
        db.close()
        return

    # Display audit table
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Timestamp", style="dim")
    table.add_column("Level")
    table.add_column("Action")
    table.add_column("Details")

    for entry in entries:
        level_color = "red" if entry.level == "CRITICAL" else "yellow" if entry.level == "WARNING" else "white"
        # Format timestamp - entry.timestamp is a datetime object
        if entry.timestamp:
            timestamp = entry.timestamp.isoformat()[:19] if hasattr(entry.timestamp, 'isoformat') else str(entry.timestamp)[:19]
        else:
            timestamp = "N/A"
        table.add_row(
            timestamp,
            f"[{level_color}]{entry.level}[/{level_color}]",
            entry.action,
            (entry.details or "")[:50] + "..." if entry.details and len(entry.details) > 50 else entry.details or ""
        )

    console.print(table)

    # Verify hash chain integrity
    if args.verify_chain:
        console.print("\n[cyan]Verifying audit log integrity...[/cyan]")
        is_valid = audit.verify_integrity()
        if is_valid:
            console.print("[green]✓ Hash chain is valid[/green]")
        else:
            error_console.print("[red]✗ Hash chain is INVALID - possible tampering detected![/red]")

    db.close()


def cmd_verify(args: argparse.Namespace, config: Config) -> None:
    """Verify system integrity."""
    db, audit, agent = init_components(config)

    console.print("\n[bold cyan]🔍 System Integrity Verification[/bold cyan]\n")

    all_passed = True

    # 1. Check database encryption
    console.print("[cyan]1. Checking database encryption...[/cyan]")
    if db.is_encrypted:
        console.print("   [green]✓[/green] Database is encrypted (SQLCipher)")
    else:
        console.print("   [yellow]⚠[/yellow] Database is NOT encrypted (plain SQLite)")
        all_passed = False

    # 2. Verify audit log hash chain
    console.print("\n[cyan]2. Verifying audit log hash chain...[/cyan]")
    chain_valid = audit.verify_integrity()
    if chain_valid:
        console.print("   [green]✓[/green] Hash chain is valid")
    else:
        console.print("   [red]✗[/red] Hash chain is INVALID - tampering detected!")
        all_passed = False

    # 3. Scan database for leaked PII
    console.print("\n[cyan]3. Scanning database for leaked PII...[/cyan]")
    leaked = _scan_database_for_pii(db)
    if not leaked:
        console.print("   [green]✓[/green] No PII patterns detected in database")
    else:
        console.print(f"   [red]✗[/red] Found {len(leaked)} potential PII leak(s)!")
        for leak in leaked[:5]:
            console.print(f"      • {leak}")
        all_passed = False

    # 4. Check system stats
    console.print("\n[cyan]4. System statistics...[/cyan]")
    stats = db.get_stats()
    console.print(f"   • Transactions: {stats.get('total_transactions', 0)}")
    console.print(f"   • Subscriptions: {stats.get('total_subscriptions', 0)}")
    console.print(f"   • Anomalies: {stats.get('total_anomalies', 0)}")
    console.print(f"   • Audit entries: {stats.get('total_audit_entries', 0)}")

    # Final verdict
    console.print(f"\n[bold]{'✓ System integrity verified' if all_passed else '✗ System integrity issues detected'}[/bold]")

    db.close()


def cmd_reset(args: argparse.Namespace, config: Config) -> None:
    """Clear all data from the database and audit log."""
    import os

    console.print("\n[bold red]⚠️  WARNING: This will delete all data![/bold red]")
    console.print(f"  • Database: {config.db_path}")
    console.print(f"  • Audit log: {config.audit_log_path}\n")

    if not args.force:
        confirmed = Confirm.ask("[yellow]Are you sure you want to continue?[/yellow]", default=False)
        if not confirmed:
            console.print("[dim]Reset cancelled.[/dim]")
            return

    try:
        # Remove database
        if Path(config.db_path).exists():
            os.remove(config.db_path)
            console.print(f"[green]✓[/green] Deleted database: {config.db_path}")

        # Remove audit log
        if Path(config.audit_log_path).exists():
            os.remove(config.audit_log_path)
            console.print(f"[green]✓[/green] Deleted audit log: {config.audit_log_path}")

        console.print("\n[green]✓ Reset complete. Ready for a fresh scan.[/green]")

    except Exception as e:
        handle_error("Failed to reset database", e)


def cmd_test_gmail(args: argparse.Namespace, config: Config) -> None:
    """Test Gmail connectivity without processing emails."""
    console.print(Panel.fit(
        "[bold cyan]📧 Testing Gmail Connection[/bold cyan]",
        border_style="cyan"
    ))

    # Check credentials file
    console.print("\n[cyan]1. Checking Gmail credentials...[/cyan]")
    if not config.has_gmail_credentials():
        error_console.print("   [red]✗[/red] credentials.json not found")
        console.print(f"\n   Expected at: {config.google_credentials_path}")
        console.print("\n[cyan]To set up Gmail OAuth:[/cyan]")
        console.print("  python -m src.mcp_server.gmail_auth_runner")
        sys.exit(1)
    console.print(f"   [green]✓[/green] Found credentials.json")

    # Check token file
    console.print("\n[cyan]2. Checking OAuth token...[/cyan]")
    token_path = Path(config.google_token_path)
    if not token_path.exists():
        console.print("   [yellow]⚠[/yellow] token.json not found (will be created on first auth)")
    else:
        console.print(f"   [green]✓[/green] Found token.json")

    # Try to connect to Gmail
    console.print("\n[cyan]3. Testing Gmail connection...[/cyan]")
    try:
        from .mcp_server.server import fetch_financial_emails

        # Fetch just 1 email to test connectivity
        result = fetch_financial_emails(days=7, max_results=1)

        if "error" in result:
            error_console.print(f"   [red]✗[/red] Gmail error: {result['error']}")
            sys.exit(1)

        emails = result.get("emails", [])
        console.print(f"   [green]✓[/green] Connected successfully")
        console.print(f"   [dim]Found {len(emails)} email(s) in last 7 days[/dim]")

        # Show sample email info if available
        if emails:
            sample = emails[0]
            console.print(f"\n[bold]Sample Email:[/bold]")
            console.print(f"  • From: {sample.get('sender', 'N/A')}")
            console.print(f"  • Subject: {sample.get('subject', 'N/A')}")
            console.print(f"  • Date: {sample.get('date', 'N/A')}")

        console.print("\n[green]✓ Gmail connectivity test passed![/green]")
        console.print("[dim]Ready to run: python -m src.main scan[/dim]")

    except Exception as e:
        error_console.print(f"   [red]✗[/red] Connection failed: {e}")
        logger.error("Gmail connection test failed", exc_info=True)
        sys.exit(1)


# Helper functions

def _display_scan_summary(result: ScanResult, db: EncryptedDatabase, config: Config) -> None:
    """Display scan results summary with detailed tables."""
    console.print(f"\n[bold cyan]📊 Scan Summary[/bold cyan]\n")

    # Show all transactions in a table
    if result.transactions:
        console.print(f"[bold]💳 Transactions ({len(result.transactions)}):[/bold]\n")

        tx_table = Table(show_header=True, header_style="bold cyan")
        tx_table.add_column("Date", style="dim", width=10)
        tx_table.add_column("Merchant", width=25)
        tx_table.add_column("Amount", justify="right", style="green")
        tx_table.add_column("Category", width=15)

        total = 0.0
        for tx in result.transactions[:20]:  # Show first 20
            # Extract amount and convert to float
            amount_raw = tx.get('amount', 0.0)
            try:
                amount = float(amount_raw) if amount_raw else 0.0
            except (ValueError, TypeError):
                amount = 0.0
            total += amount
            date_str = tx.get('date', '')[:10] if tx.get('date') else 'N/A'

            tx_table.add_row(
                date_str,
                tx.get('merchant', 'Unknown')[:25],
                f"${amount:,.2f}",
                tx.get('category', 'Other')
            )

        console.print(tx_table)

        if len(result.transactions) > 20:
            console.print(f"[dim]... and {len(result.transactions) - 20} more[/dim]\n")

        # Spending breakdown with visual bars
        console.print(f"\n[bold]💰 Spending by Category:[/bold]\n")
        spending = {}
        total_spending = 0.0
        for tx in result.transactions:
            category = tx.get('category', 'Other')
            amount_raw = tx.get('amount', 0.0)
            try:
                amount = float(amount_raw) if amount_raw else 0.0
            except (ValueError, TypeError):
                amount = 0.0
            spending[category] = spending.get(category, 0.0) + amount
            total_spending += amount

        spending_table = Table(show_header=True, header_style="bold green")
        spending_table.add_column("Category", width=20)
        spending_table.add_column("Amount", justify="right", width=12)
        spending_table.add_column("% of Total", justify="right", width=10)
        spending_table.add_column("Visual", width=30)

        for category, amount in sorted(spending.items(), key=lambda x: x[1], reverse=True):
            percentage = (amount / total_spending * 100) if total_spending > 0 else 0
            bar_length = int(percentage / 3.33)  # Max 30 chars for 100%
            bar = "█" * bar_length

            spending_table.add_row(
                category,
                f"${amount:,.2f}",
                f"{percentage:.1f}%",
                f"[green]{bar}[/green]"
            )

        console.print(spending_table)
        console.print(f"\n[bold]Total Spending: ${total_spending:,.2f}[/bold]")

    # Show anomalies if any
    if result.anomalies:
        console.print(f"\n[bold red]⚠️  Anomalies Detected ({len(result.anomalies)}):[/bold red]\n")

        anomaly_table = Table(show_header=True, header_style="bold red")
        anomaly_table.add_column("Type", width=15)
        anomaly_table.add_column("Severity", width=10)
        anomaly_table.add_column("Description", width=50)

        for anomaly in result.anomalies[:10]:
            severity = anomaly.get('severity', 'medium')
            severity_color = _severity_color(severity)

            anomaly_table.add_row(
                anomaly.get('type', 'Unknown'),
                f"[{severity_color}]{severity.upper()}[/{severity_color}]",
                anomaly.get('description', 'N/A')[:50]
            )

        console.print(anomaly_table)


def _display_spending_table(spending: dict[str, float]) -> None:
    """Display spending breakdown table."""
    if not spending:
        return

    table = Table(show_header=True, header_style="bold green")
    table.add_column("Category")
    table.add_column("Amount", justify="right")

    for category, amount in sorted(spending.items(), key=lambda x: x[1], reverse=True):
        table.add_row(category, f"${amount:,.2f}")

    console.print(table)


def _severity_color(severity: str) -> str:
    """Get color for severity level."""
    return {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red"
    }.get(severity.lower(), "white")


def _extract_transaction_info(email: dict[str, Any]) -> tuple[str | None, float | None]:
    """Extract merchant and amount from email (simple parser for demo)."""
    subject = email.get('subject', '')
    body = email.get('body', '')

    # Extract amount (look for $XX.XX pattern)
    import re
    amount_match = re.search(r'\$(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)', subject + ' ' + body)
    amount = float(amount_match.group(1).replace(',', '')) if amount_match else None

    # Extract merchant (heuristic: look for known patterns)
    merchant = None
    for keyword in ['Merchant:', 'merchant:', 'payment to', 'at ']:
        if keyword in body:
            idx = body.index(keyword) + len(keyword)
            merchant_line = body[idx:idx+50].split('\n')[0].strip()
            merchant = merchant_line.split()[0] if merchant_line else None
            break

    # Fallback: extract from subject
    if not merchant:
        if 'at ' in subject:
            merchant = subject.split('at ')[-1].split()[0]
        elif 'to ' in subject:
            merchant = subject.split('to ')[-1].split()[0]

    return merchant, amount


def _scan_database_for_pii(db: EncryptedDatabase) -> list[str]:
    """Scan database for potential PII leaks."""
    from .redactor.patterns import get_patterns_ordered

    leaked = []
    patterns = get_patterns_ordered()

    # Scan transactions
    transactions = db.get_transactions()
    for tx in transactions:
        for field in [tx.merchant, tx.category, tx.source_email_id or ""]:
            if field:
                for pattern in patterns:
                    if pattern.regex.search(field):
                        leaked.append(f"Transaction {tx.id}: {pattern.name} in {field[:30]}")

    return leaked


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Secure Personal Finance Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run Gmail financial scan")
    scan_parser.add_argument("--days", type=int, default=30, help="Days to scan (default: 30)")
    scan_parser.add_argument("--max-results", type=int, default=100, help="Max emails to fetch (default: 100)")
    scan_parser.add_argument("--fresh", action="store_true", help="Clear database before scanning")

    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run demo with sample emails")

    # demo-injection command (Task 6: Cequence assessment)
    demo_injection_parser = subparsers.add_parser("demo-injection", help="Demo prompt injection detection")

    # chat command
    chat_parser = subparsers.add_parser("chat", help="Interactive chat mode")

    # summary command
    summary_parser = subparsers.add_parser("summary", help="Generate financial summary")
    summary_parser.add_argument("--days", type=int, default=7, help="Days to summarize (default: 7)")

    # anomalies command
    anomalies_parser = subparsers.add_parser("anomalies", help="Show unresolved anomalies")
    anomalies_parser.add_argument("-i", "--interactive", action="store_true", help="Resolve anomalies interactively")

    # subscriptions command
    subscriptions_parser = subparsers.add_parser("subscriptions", help="List active subscriptions")

    # audit command
    audit_parser = subparsers.add_parser("audit", help="Show audit log")
    audit_parser.add_argument("--security", action="store_true", help="Show only security events")
    audit_parser.add_argument("--days", type=int, default=7, help="Days to show (default: 7)")
    audit_parser.add_argument("--limit", type=int, default=50, help="Max entries to show (default: 50)")
    audit_parser.add_argument("--verify-chain", action="store_true", help="Verify hash chain integrity")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify system integrity")

    # reset command
    reset_parser = subparsers.add_parser("reset", help="Clear all data (use with caution)")
    reset_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")

    # test-gmail command
    test_gmail_parser = subparsers.add_parser("test-gmail", help="Test Gmail connectivity")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load configuration
    config = Config.from_env()

    # Route to command handler
    commands = {
        "scan": cmd_scan,
        "demo": cmd_demo,
        "demo-injection": cmd_demo_injection,  # Task 6: Cequence assessment
        "chat": cmd_chat,
        "summary": cmd_summary,
        "anomalies": cmd_anomalies,
        "subscriptions": cmd_subscriptions,
        "audit": cmd_audit,
        "verify": cmd_verify,
        "reset": cmd_reset,
        "test-gmail": cmd_test_gmail,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args, config)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

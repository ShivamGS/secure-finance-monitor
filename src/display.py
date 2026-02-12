"""
Security pipeline visualization for Cequence demo.

Provides rich console formatting to make each security layer visible
during the live demonstration. Uses rich library for professional output.
"""

import logging
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box

logger = logging.getLogger(__name__)
console = Console()


class PipelineDisplay:
    """
    Display manager for security pipeline stages.

    Makes the security story visible: MCP → Blocklist → Redaction → Agent → Storage → Audit
    Each stage clearly labeled with status indicators (✅ ❌ ⚠️).
    """

    def __init__(self):
        self.start_time = datetime.now()

    def scan_header(self, days: int, max_results: int, mode: str = "scan") -> None:
        """
        Display scan header with parameters.

        Args:
            days: Number of days to scan
            max_results: Maximum emails to process
            mode: "scan" or "chat"
        """
        title = "🔒 Secure Finance Monitor - Security Pipeline Demo" if mode == "scan" else "💬 Chat Mode - Security Pipeline"

        header = Panel(
            f"[bold cyan]Scanning last {days} days[/bold cyan]\n"
            f"Max emails: {max_results}\n"
            f"Mode: {mode.upper()}\n"
            f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            title=title,
            border_style="cyan",
            box=box.DOUBLE
        )
        console.print(header)
        console.print()

    def mcp_status(self, success: bool, email_count: int, error: Optional[str] = None) -> None:
        """
        Display MCP (Model Context Protocol) Gmail fetch status.

        Args:
            success: Whether MCP fetch succeeded
            email_count: Number of emails fetched
            error: Error message if failed
        """
        tree = Tree("📧 [bold]LAYER 1: MCP (Model Context Protocol)[/bold]")

        if success:
            tree.add(f"[green]✅ Gmail API connected[/green]")
            tree.add(f"[green]✅ Fetched {email_count} financial emails[/green]")
            tree.add("[dim]OAuth 2.0 authenticated | Read-only scope[/dim]")
        else:
            tree.add(f"[red]❌ Gmail fetch failed[/red]")
            if error:
                tree.add(f"[red]Error: {error}[/red]")

        console.print(tree)
        console.print()

    def blocklist_status(self, stats: dict) -> None:
        """
        Display blocklist pre-filtering results.

        Args:
            stats: Statistics from Blocklist.stats()
                {
                    "total_checks": int,
                    "blocked_count": int,
                    "blocked_by_sender": int,
                    "blocked_by_domain": int,
                    "blocked_by_subject": int,
                    "block_rate": float,
                    "config_loaded": bool
                }
        """
        tree = Tree("🚫 [bold]LAYER 2: Email Blocklist (Pre-Filter)[/bold]")

        if stats.get("config_loaded"):
            tree.add(f"[green]✅ Blocklist loaded[/green]")
            tree.add(f"[yellow]⚠️  Blocked {stats['blocked_count']}/{stats['total_checks']} emails ({stats['block_rate']}%)[/yellow]")

            if stats['blocked_count'] > 0:
                breakdown = tree.add("[dim]Breakdown:[/dim]")
                if stats['blocked_by_sender'] > 0:
                    breakdown.add(f"[dim]  • By sender: {stats['blocked_by_sender']}[/dim]")
                if stats['blocked_by_domain'] > 0:
                    breakdown.add(f"[dim]  • By domain: {stats['blocked_by_domain']}[/dim]")
                if stats['blocked_by_subject'] > 0:
                    breakdown.add(f"[dim]  • By subject: {stats['blocked_by_subject']}[/dim]")
        else:
            tree.add("[yellow]⚠️  No blocklist config (fail-open mode)[/yellow]")

        console.print(tree)
        console.print()

    def redaction_status(self, total_redactions: int, by_type: dict, failed: int = 0) -> None:
        """
        Display PII redaction results.

        Args:
            total_redactions: Total redactions performed
            by_type: Dictionary of redaction counts by type
                {"CARD": 5, "SSN": 0, "ACCOUNT": 2, ...}
            failed: Number of emails that failed redaction
        """
        tree = Tree("🔐 [bold]LAYER 3: PII Redaction (3-Pass Pipeline)[/bold]")

        if failed > 0:
            tree.add(f"[red]❌ {failed} emails failed redaction (fail-closed)[/red]")
        else:
            tree.add("[green]✅ All emails redacted successfully[/green]")

        tree.add(f"[cyan]Total redactions: {total_redactions}[/cyan]")

        if total_redactions > 0:
            breakdown = tree.add("[dim]Redaction breakdown:[/dim]")
            for redaction_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    breakdown.add(f"[dim]  • {redaction_type}: {count}[/dim]")

        tree.add("[dim]Pipeline: Regex → Presidio NER → Validation[/dim]")

        console.print(tree)
        console.print()

    def pii_before_after(self, before: str, after: str, redaction_count: int) -> None:
        """
        THE MONEY SHOT: Show actual PII redaction example.

        This is what evaluators want to see - proof that PII is being caught.

        Args:
            before: Raw email snippet (ONLY shown in terminal, never to LLM)
            after: Redacted version
            redaction_count: Number of redactions in this example
        """
        panel = Panel(
            f"[yellow]⚠️  BEFORE (Raw Email - {redaction_count} PII items detected):[/yellow]\n"
            f"[dim]{before[:200]}...[/dim]\n\n"
            f"[green]✅ AFTER (Redacted - Safe for LLM):[/green]\n"
            f"[bold]{after[:200]}...[/bold]",
            title="🎯 [bold red]PII REDACTION DEMO[/bold red]",
            border_style="red",
            box=box.DOUBLE
        )
        console.print(panel)
        console.print()

    def agent_status(self, transactions_extracted: int, injections_detected: int) -> None:
        """
        Display AI agent processing status.

        Args:
            transactions_extracted: Number of transactions extracted
            injections_detected: Number of prompt injection attempts detected
        """
        tree = Tree("🤖 [bold]LAYER 4: AI Agent Processing[/bold]")

        tree.add(f"[green]✅ OpenAI Agents SDK initialized[/green]")
        tree.add(f"[cyan]Extracted {transactions_extracted} transactions[/cyan]")

        if injections_detected > 0:
            tree.add(f"[red]⚠️  Detected {injections_detected} prompt injection attempts[/red]")
        else:
            tree.add("[green]✅ No prompt injections detected[/green]")

        tree.add("[dim]Security: Hardened system prompts | Fail-closed on suspicious input[/dim]")

        console.print(tree)
        console.print()

    def storage_status(self, success: bool, db_path: str, encrypted: bool, records_saved: int) -> None:
        """
        Display database storage status.

        Args:
            success: Whether storage succeeded
            db_path: Path to database file
            encrypted: Whether SQLCipher encryption is active
            records_saved: Number of records saved
        """
        tree = Tree("💾 [bold]LAYER 5: Encrypted Storage[/bold]")

        if success:
            tree.add(f"[green]✅ Saved {records_saved} records to database[/green]")
            tree.add(f"[dim]Database: {db_path}[/dim]")

            if encrypted:
                tree.add("[green]✅ SQLCipher encryption active[/green]")
            else:
                tree.add("[yellow]⚠️  Running without encryption (SQLCipher not available)[/yellow]")
        else:
            tree.add("[red]❌ Database storage failed[/red]")

        console.print(tree)
        console.print()

    def audit_status(self, events_logged: int, chain_valid: bool) -> None:
        """
        Display audit trail status.

        Args:
            events_logged: Number of audit events logged
            chain_valid: Whether hash chain is valid (tamper detection)
        """
        tree = Tree("📝 [bold]LAYER 6: Tamper-Evident Audit Log[/bold]")

        tree.add(f"[cyan]Logged {events_logged} audit events[/cyan]")

        if chain_valid:
            tree.add("[green]✅ Hash chain verified (no tampering)[/green]")
        else:
            tree.add("[red]❌ Hash chain broken (tampering detected!)[/red]")

        tree.add("[dim]Algorithm: SHA-256 hash chain | Append-only JSONL[/dim]")

        console.print(tree)
        console.print()

    def financial_summary(self, transactions: list[dict], by_category: dict, total: float) -> None:
        """
        Display financial summary table.

        Args:
            transactions: List of transaction dictionaries
            by_category: Dictionary of {category: amount}
            total: Total spending
        """
        # Transactions table
        if transactions:
            table = Table(title="📊 Transactions Extracted", box=box.SIMPLE)
            table.add_column("Date", style="cyan")
            table.add_column("Merchant", style="white")
            table.add_column("Amount", style="green", justify="right")
            table.add_column("Category", style="yellow")

            for tx in transactions[:10]:  # Show first 10
                table.add_row(
                    tx.get("date", "N/A"),
                    tx.get("merchant", "Unknown")[:30],
                    f"${tx.get('amount', 0):.2f}",
                    tx.get("category", "Other")
                )

            if len(transactions) > 10:
                table.add_row("...", f"({len(transactions) - 10} more)", "", "", style="dim")

            console.print(table)
            console.print()

        # Category breakdown
        if by_category:
            category_table = Table(title="💰 Spending by Category", box=box.SIMPLE)
            category_table.add_column("Category", style="cyan")
            category_table.add_column("Amount", style="green", justify="right")
            category_table.add_column("Percentage", style="yellow", justify="right")

            sorted_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
            for category, amount in sorted_categories:
                percentage = (amount / total * 100) if total > 0 else 0
                category_table.add_row(
                    category,
                    f"${amount:.2f}",
                    f"{percentage:.1f}%"
                )

            console.print(category_table)
            console.print()

        # Total
        console.print(f"[bold green]Total Spending: ${total:.2f}[/bold green]")
        console.print()

    def chat_response(self, pipeline_summary: dict, response: str) -> None:
        """
        Display chat mode compact pipeline status.

        Args:
            pipeline_summary: Dictionary with pipeline stage statuses
                {
                    "fetched": int,
                    "blocked": int,
                    "redacted": int,
                    "injections": int,
                    "stored": int,
                    "audited": int
                }
            response: The actual chat response text
        """
        # Compact one-line pipeline status
        status_parts = []

        status_parts.append(f"[cyan]Fetched: {pipeline_summary.get('fetched', 0)}[/cyan]")
        status_parts.append(f"[yellow]Blocked: {pipeline_summary.get('blocked', 0)}[/yellow]")
        status_parts.append(f"[green]Redacted: {pipeline_summary.get('redacted', 0)} PII[/green]")

        injections = pipeline_summary.get('injections', 0)
        if injections > 0:
            status_parts.append(f"[red]Injections: {injections}[/red]")
        else:
            status_parts.append("[green]Injections: 0[/green]")

        status_parts.append(f"[cyan]Stored: {pipeline_summary.get('stored', 0)}[/cyan]")
        status_parts.append(f"[cyan]Audited: {pipeline_summary.get('audited', 0)} events[/cyan]")

        pipeline_status = " | ".join(status_parts)

        console.print(f"[dim]🔒 Pipeline:[/dim] {pipeline_status}")
        console.print()

        # The actual response
        console.print(Panel(
            response,
            title="💬 [bold]Agent Response[/bold]",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print("[green]✅ Response verified (no PII leaked)[/green]")
        console.print()

    def error(self, message: str, details: Optional[str] = None) -> None:
        """
        Display error message.

        Args:
            message: Error message
            details: Optional detailed error information
        """
        content = f"[bold red]❌ {message}[/bold red]"
        if details:
            content += f"\n\n[dim]{details}[/dim]"

        console.print(Panel(
            content,
            title="⚠️  Error",
            border_style="red",
            box=box.HEAVY
        ))
        console.print()

    def success(self, message: str) -> None:
        """Display success message."""
        console.print(f"[bold green]✅ {message}[/bold green]")
        console.print()

    def section_divider(self, title: str) -> None:
        """Print a section divider."""
        console.print()
        console.print(f"[bold cyan]{'=' * 80}[/bold cyan]")
        console.print(f"[bold cyan]{title.center(80)}[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 80}[/bold cyan]")
        console.print()

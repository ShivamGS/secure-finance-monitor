# Sample Outputs

Example outputs from each command, generated against a real Gmail inbox.

| File | Command | Description |
|------|---------|-------------|
| [01_scan.md](01_scan.md) | `python -m src.main scan --days 30` | Full 6-layer security pipeline scan with 100 emails fetched, 21 blocked, 168 PII items redacted, 16 transactions extracted |
| [02_chat.md](02_chat.md) | `python -m src.main chat` | Interactive chat session showing transaction queries, merchant analysis, and anomaly detection with pipeline stats on every response |
| [03_summary.md](03_summary.md) | `python -m src.main summary --days 30` | Transaction summary table with category breakdown and visual spending bars |
| [04_demo_injection.md](04_demo_injection.md) | `python -m src.main demo-injection` | Prompt injection detection demo showing 2 flagged emails (msg-010 and msg-015) with 73 PII items redacted |

**Note:** These outputs were generated against a real Gmail inbox. PII in the original emails was redacted by the 3-pass pipeline before reaching the AI agent.

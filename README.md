# 🔒 Secure Personal Finance Monitor

An agentic AI system that monitors personal finances via Gmail while ensuring PII never reaches the LLM. Built for the Cequence AI internship assessment.

## Architecture

```
                        SECURE PERSONAL FINANCE MONITOR
 ┌─────────────────────────────────────────────────────────────────────┐
 │                                                                     │
 │  ┌───────────────┐    ┌──────────────────────┐    ┌──────────────┐ │
 │  │  GMAIL API    │    │   SECURITY WALL      │    │  AI AGENT    │ │
 │  │  (MCP Server) │───>│                      │───>│  (OpenAI     │ │
 │  │               │    │  Pass 1: Regex (10+  │    │   Agents SDK)│ │
 │  │  - Read-only  │    │          patterns)   │    │              │ │
 │  │  - OAuth2     │    │  Pass 2: Presidio    │    │  - Categorize│ │
 │  │  - Financial  │    │          NER         │    │  - Anomalies │ │
 │  │    senders    │    │  Pass 3: Validator   │    │  - Summaries │ │
 │  │               │    │          sweep       │    │  - Injection │ │
 │  └───────────────┘    │                      │    │    detection │ │
 │                       │  FAIL CLOSED:        │    │              │ │
 │                       │  Error = no content  │    │  Output also │ │
 │                       │  passes through      │    │  sanitized   │ │
 │                       └──────────────────────┘    └──────┬───────┘ │
 │                                                          │         │
 │  ┌───────────────────────────────────────────────────────┘         │
 │  │                                                                 │
 │  v                                                                 │
 │  ┌──────────────────────┐    ┌────────────────────────────────┐   │
 │  │  ENCRYPTED STORAGE   │    │  AUDIT LOG                     │   │
 │  │  (SQLCipher)         │    │                                │   │
 │  │                      │    │  - Hash-chained entries        │   │
 │  │  - Transactions      │    │  - Tamper detection            │   │
 │  │  - Subscriptions     │    │  - Dual write: DB + JSONL      │   │
 │  │  - Anomalies         │    │  - Every action logged         │   │
 │  │  - Metadata ONLY     │    │  - CRITICAL events to stderr   │   │
 │  │  - No raw content    │    │                                │   │
 │  └──────────────────────┘    └────────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────────────┘
```

**Data Flow:** Gmail API → Blocklist → PII Redactor (3-pass, no LLM) → Sanitized Data → AI Agent → Encrypted DB + Audit Log

## Security Pipeline (6 Layers)

1. **MCP Gateway** — Gmail API with `gmail.readonly` scope, OAuth 2.0
2. **Email Blocklist** — Configurable sender/domain/subject pre-filter (`config/blocklist.json`)
3. **PII Redaction** — 3-pass pipeline: Regex (10 patterns) → Presidio NER → Validator sweep. Fail-closed.
4. **Agent Security** — Prompt injection detection (10+ patterns), hardened system prompts, output re-scanning
5. **Encrypted Storage** — SQLCipher AES-256 (graceful fallback), metadata only, no raw content stored
6. **Audit Trail** — SHA-256 hash chain, dual-write (DB + JSONL), tamper-evident, CRITICAL to stderr

## Quick Start

### Prerequisites
- Python 3.10+
- Google Cloud project with Gmail API enabled
- OpenAI API key (or Anthropic, or run in mock mode)

### Setup
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
cp .env.example .env  # Add your API keys
```

### Usage
```bash
# Live Gmail scan with 9-stage security pipeline
python -m src.main scan --days 7

# Interactive chat mode
python -m src.main chat

# Demo with sample data (no API keys needed)
python -m src.main demo

# Prompt injection defense demo
python -m src.main demo-injection
```

### Tests
```bash
python -m pytest tests/ -v  # All tests
```

## Tech Stack

- **Agent**: OpenAI Agents SDK
- **MCP**: FastMCP
- **PII**: Presidio + spaCy + regex
- **DB**: SQLCipher
- **Audit**: SHA-256 hash chain
- **Display**: Rich console library

## Project Structure

```
secure-finance-monitor/
├── src/
│   ├── main.py                    # CLI entry point
│   ├── config/
│   │   ├── settings.py            # Environment configuration
│   │   └── blocklist.py           # Email pre-filter
│   ├── agent/
│   │   ├── finance_agent.py       # OpenAI Agents wrapper
│   │   ├── tools.py               # Agent function tools
│   │   ├── extractor.py           # Smart transaction extraction
│   │   └── prompts.py             # Security-hardened prompts
│   ├── mcp_server/
│   │   ├── server.py              # FastMCP Gmail server
│   │   └── gmail_client.py        # Gmail API wrapper
│   ├── redactor/
│   │   ├── pii_redactor.py        # 3-pass PII pipeline
│   │   ├── patterns.py            # Regex patterns
│   │   └── validator.py           # Final safety sweep
│   ├── storage/
│   │   ├── database.py            # SQLCipher interface
│   │   ├── audit.py               # Hash-chained logger
│   │   └── models.py              # Data models
│   └── display.py                 # Rich pipeline visualization
├── config/
│   └── blocklist.json             # Promotional email filters
├── tests/                         # 174 tests
└── demo/
    └── sample_emails.json         # Sample data
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Anthropic API key (alternative) | - |
| `GOOGLE_CREDENTIALS_PATH` | Gmail OAuth credentials | `./credentials.json` |
| `DB_PATH` | Database file path | `finance_monitor.db` |
| `DB_ENCRYPTION_KEY` | SQLCipher encryption key (32-byte) | - |
| `FAIL_CLOSED` | Withhold content on redaction failure | `true` |

See `.env.example` for full list.

## Security Design

See [SECURITY_DESIGN.md](SECURITY_DESIGN.md) for threat model and defense-in-depth analysis.

## Documentation

- [CLI_COMMANDS.md](CLI_COMMANDS.md) - Complete command reference
- [IMPROVEMENTS_SUMMARY.md](IMPROVEMENTS_SUMMARY.md) - Email filtering & accuracy improvements
- [CEQUENCE_DEMO_READY.md](CEQUENCE_DEMO_READY.md) - Live demo implementation guide
- [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) - Development context for Claude Code

## License

MIT

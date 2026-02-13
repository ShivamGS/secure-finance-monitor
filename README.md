# 🔒 Secure Personal Finance Monitor

Security-first AI agent for monitoring personal finances via Gmail with zero PII exposure to LLMs.

> **See [Sample Outputs](docs/sample_outputs/)** for real-world examples of scan, chat, summary, and injection detection.

## Architecture

```
                        SECURE PERSONAL FINANCE MONITOR
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                                                                             │
 │  ┌────────────────────────────────────────────────────────────────────┐    │
 │  │                    MCP SERVER (Layer 1)                             │    │
 │  │                    Security Boundary - Nothing Raw Escapes          │    │
 │  │                                                                      │    │
 │  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐  ┌──────────────┐  │    │
 │  │  │  GMAIL   │─>│ BLOCKLIST │─>│ PII REDACTOR │─>│ TRANSACTION  │  │    │
 │  │  │   API    │  │ (Layer 2) │  │  (Layer 3)   │  │  EXTRACTOR   │  │    │
 │  │  │          │  │           │  │              │  │              │  │    │
 │  │  │Read-only │  │- Spam     │  │3-pass:       │  │Regex-based   │  │    │
 │  │  │OAuth2    │  │- Promo    │  │1. Regex      │  │parsing       │  │    │
 │  │  │Financial │  │- Marketing│  │2. Presidio   │  │              │  │    │
 │  │  │senders   │  │- Sender   │  │3. Validator  │  │              │  │    │
 │  │  │          │  │  filter   │  │FAIL CLOSED   │  │              │  │    │
 │  │  └──────────┘  └───────────┘  └──────────────┘  └──────┬───────┘  │    │
 │  │                                                         │          │    │
 │  └─────────────────────────────────────────────────────────┼──────────┘    │
 │                                                            │               │
 │                                    Sanitized JSON only     │               │
 │                                    (no PII, no raw emails) │               │
 │                                                            v               │
 │                                            ┌──────────────────────────────┐ │
 │                                            │  AI AGENT (Layer 4)          │ │
 │                                            │  (OpenAI Agents SDK)         │ │
 │                                            │                              │ │
 │                                            │  - Categorization            │ │
 │                                            │  - Anomaly detection         │ │
 │                                            │  - Injection detection       │ │
 │                                            │  - Output sanitization       │ │
 │                                            └──────────────┬───────────────┘ │
 │                                                           │                 │
 │  ┌────────────────────────────────────────────────────────┘                 │
 │  │                                                                          │
 │  v                                                                          │
 │  ┌──────────────────────┐    ┌────────────────────────────────────────┐    │
 │  │  ENCRYPTED STORAGE   │    │  AUDIT LOG (Layer 6)                   │    │
 │  │  (Layer 5)           │    │                                        │    │
 │  │  (SQLCipher)         │    │  - Hash-chained entries                │    │
 │  │                      │    │  - Tamper detection                    │    │
 │  │  - Transactions      │    │  - Dual write: DB + JSONL              │    │
 │  │  - Subscriptions     │    │  - Every action logged                 │    │
 │  │  - Anomalies         │    │  - CRITICAL events                     │    │
 │  │  - Metadata ONLY     │    │                                        │    │
 │  │  - No raw content    │    │                                        │    │
 │  └──────────────────────┘    └────────────────────────────────────────┘    │
 └─────────────────────────────────────────────────────────────────────────────┘
```

**Data Flow:** Gmail API → Blocklist → PII Redactor → Transaction Extractor *(all within MCP server)* → Sanitized JSON → AI Agent → Encrypted DB + Audit Log

## Security Pipeline

| Layer | Component | Function | Failure Mode |
|-------|-----------|----------|--------------|
| 1 | **MCP Server** | Gmail API (OAuth 2.0, `gmail.readonly`) + Blocklist + PII Redaction (3-pass) + Transaction Extraction | Token.json theft exposes read-only access; extraction may miss transactions |
| 2 | **Email Blocklist** | Pre-filter spam/promotional emails by sender/domain/subject | Misconfiguration may block legitimate transactions; no security impact |
| 3 | **PII Redaction** | 3-pass pipeline: Regex (10 patterns) → Presidio NER → Validator | **FAIL CLOSED** — errors withhold content; some PII patterns may be missed |
| 4 | **Agent Security** | Prompt injection detection (10 patterns), hardened prompts, output re-scanning | Injection may bypass detection; redaction wall bounds damage |
| 5 | **Encrypted Storage** | SQLCipher AES-256 (graceful fallback to plaintext if unavailable) | Encryption key in environment variable; no key rotation |
| 6 | **Audit Trail** | SHA-256 hash-chained log, dual-write (DB + JSONL), tamper-evident | Last entry can be modified without breaking chain; no external anchor |

## PII Redaction Patterns

| Pattern | Example | Replacement | Priority |
|---------|---------|-------------|----------|
| Credit Card | `4532-8821-7744-3847` | `[CARD_****3847]` | 10 (highest) |
| Masked Card | `****1234` | Preserved as-is | 5 |
| SSN | `123-45-6789` | `[SSN_REDACTED]` | 20 |
| Routing Number | `021000021` | `[ROUTING_REDACTED]` | 25 |
| Account Number | `Account #12345678` | `[ACCT_REDACTED]` | 30 |
| Generic Long Number | `#114-3948572-8837261` | `[ORDER_REDACTED]` | 35 |
| Phone Number | `(555) 123-4567` | `[PHONE_REDACTED]` | 40 |
| Secure URL | `https://secure.example.com/verify?token=abc` | `[SECURE_URL_REDACTED]` | 45 |
| Email Address | `user@example.com` | `[EMAIL_REDACTED]` | 50 |
| Physical Address | `123 Main St, San Francisco CA 94102` | `[ADDRESS_REDACTED]` | 55 |

**Note:** Dollar amounts (`$123.45`), merchant names, dates, and redaction tags are intentionally preserved — the agent needs them for analysis.

## MCP (Model Context Protocol) Architecture

The system uses proper MCP client-server architecture for secure Gmail integration:

```
Agent (MCP Client)              MCP Server (stdio)              Gmail API
     │                                │                              │
     │  MCPServerStdio                │  FastMCP                     │
     │  - 60s timeout                 │  - Blocklist filter          │
     │  - Auto-discover tools         │  - PII redaction (3-pass)    │
     │                                │  - Transaction extraction    │
     │                                │                              │
     ├──────call_tool()──────────────>│────────read emails──────────>│
     │   fetch_financial_emails       │                              │
     │   {days: 30, max_results: 100} │                              │
     │                                │<─────raw email data──────────┤
     │                                │                              │
     │                                │  [SECURITY PIPELINE]         │
     │                                │  1. Apply blocklist          │
     │                                │  2. Redact PII               │
     │                                │  3. Extract transactions     │
     │                                │                              │
     │<────JSON response───────────────┤                              │
     │  {transactions: [...],         │                              │
     │   pipeline_stats: {            │                              │
     │     fetched: 100,              │                              │
     │     blocked: 20,               │                              │
     │     redacted: 265              │                              │
     │   }}                           │                              │
```

**Key Features:**
- **Stdio Transport**: MCP server runs as subprocess, communicates via stdin/stdout
- **Security Boundary**: Full pipeline (blocklist → redaction → extraction) runs in MCP server
- **Agent Never Sees Raw Data**: Returns only sanitized transaction metadata
- **60-Second Timeout**: Configured for large email batch processing
- **Pipeline Stats**: Real-time visibility into security layers (fetched, blocked, redacted counts)

**Running MCP Server Standalone:**
```bash
# Start MCP server (for debugging)
python -m src.mcp_server
```

## Quick Start

### Prerequisites
- Python 3.10+
- Google Cloud project with Gmail API enabled
- OpenAI API key (or Anthropic API key, or use mock mode)
- SQLCipher library (`brew install sqlcipher` on macOS) — optional, falls back to unencrypted SQLite

### Setup
```bash
# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Configure environment
cp .env.example .env  # Add your API keys

# Set up Gmail OAuth (follow prompts)
python -m src.mcp_server.gmail_auth_runner

# Run tests
python -m pytest tests/ -v
```

### All CLI Commands
```bash
# Scan Gmail for financial emails
python -m src.main scan --days 30 --max-results 100

# Interactive chat mode
python -m src.main chat

# View saved transactions
python -m src.main summary --days 30

# Check for anomalies
python -m src.main anomalies

# List subscriptions
python -m src.main subscriptions

# Verify audit integrity
python -m src.main verify

# Demo mode (no API keys needed)
python -m src.main demo

# Prompt injection defense demo
python -m src.main demo-injection

# Test Gmail connection
python -m src.main test-gmail

# Reset database (clear all data)
python -m src.main reset --confirm
```

## Chat Mode

The interactive chat mode supports natural language queries about your finances:

**Example Queries:**
- `last 30 days transactions` - View all transactions
- `which merchants did I pay the most` - Top merchants by spending
- `show me any suspicious transactions` - Anomaly detection
- `how much did I spend on groceries` - Category-specific analysis
- `find duplicate charges` - Detect duplicates
- `show me my subscriptions` - Recurring charges

**Pipeline Stats:**
Every chat response shows real-time security pipeline statistics:
```
🔒 Pipeline: Fetched: 79 | Blocked: 21 | Redacted: 168 PII | Injections: 0 | Stored: 16 | Audited: 1 events
```

**Features:**
- 🔒 Zero PII exposure — all emails redacted before reaching the AI
- 📊 Real-time pipeline stats on every response
- 🛡️ Automatic prompt injection detection
- 💬 Natural language — no commands to memorize
- 🔄 Fresh data fetched from Gmail for every query

## Module Structure

```
secure-finance-monitor/
├── src/
│   ├── main.py               # CLI entry point
│   ├── config/               # Environment configuration and blocklist
│   ├── agent/                # OpenAI Agents SDK wrapper, tools, prompts
│   ├── mcp_server/           # FastMCP Gmail server, OAuth, API client
│   ├── redactor/             # 3-pass PII pipeline: regex, Presidio, validator
│   ├── storage/              # SQLCipher database, hash-chained audit log
│   └── display.py            # Rich console pipeline visualization
├── config/
│   └── blocklist.json        # Email filters (senders, domains, subjects)
├── tests/                    # 183 tests
├── demo/
│   └── sample_emails.json    # Demo data (15 sample emails)
└── docs/
    ├── sample_outputs/       # Example command outputs
    └── WHAT_COULD_BREAK.md   # Failure mode analysis
```

## How Components Connect

**Scan Flow (Direct MCP):**
`main.py:cmd_scan` → MCP client → `mcp_server/server.py:fetch_financial_emails` → `blocklist.py:is_blocked` → `pii_redactor.py:redact` → `extractor.py:extract_transaction` → returns sanitized JSON → `storage/database.py:save_transactions` → `storage/audit.py:log_email_processed`

**Chat Flow (Agent + MCP):**
`main.py:cmd_chat` → `finance_agent.py:FinanceAgent.chat` → Agent calls MCP tool → `mcp_server/server.py:fetch_financial_emails` OR `get_financial_summary` → (same security pipeline) → Agent receives sanitized JSON → `finance_agent.py:sanitize_response` → `storage/audit.py:log_response_sent`

**Both paths use identical MCP security pipeline: Gmail API → Blocklist → PII Redaction → Transaction Extraction**

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | - | No (falls back to mock) |
| `ANTHROPIC_API_KEY` | Anthropic API key | - | No (alternative to OpenAI) |
| `MODEL_PROVIDER` | LLM provider (`openai`, `anthropic`, `mock`) | auto-detect | No |
| `AGENT_MODEL` | Agent model name | `gpt-4o-mini` | No |
| `GOOGLE_CREDENTIALS_PATH` | Gmail OAuth credentials | `./credentials.json` | For live Gmail |
| `GOOGLE_TOKEN_PATH` | Cached OAuth token | `./token.json` | Auto-generated |
| `DB_PATH` | Database file path | `finance_monitor.db` | No |
| `DB_ENCRYPTION_KEY` | SQLCipher 32-byte key | - | No (falls back to plaintext) |
| `AUDIT_LOG_PATH` | JSONL audit log path | `audit.jsonl` | No |
| `MAX_EMAILS_PER_SCAN` | Max emails per scan | `100` | No |
| `SCAN_DAYS` | Default lookback period | `30` | No |
| `FAIL_CLOSED` | Withhold content on redaction error | `true` | No |

See `.env.example` for complete list.

## Design Decisions

- **Pattern priority ordering** — GENERIC_LONG_NUMBER (35) runs before PHONE_NUMBER (40) so order numbers like `#114-3948572-8837261` match context-aware pattern first
- **Presidio filtering** — Skips DATE_TIME and URL entities, and already-redacted `[..._REDACTED]` spans to avoid double-redaction
- **Validator safe contexts** — Dollar amounts, dates, redaction tags, store numbers, ZIP codes whitelisted to prevent over-redaction
- **SQLCipher row format** — When encrypted, `row_factory` is None (returns tuples); all helper functions handle both tuple and sqlite3.Row formats
- **LLM auto-detection** — Checks OPENAI_API_KEY → ANTHROPIC_API_KEY → falls back to MockBackend for testing
- **Audit hash chain** — Genesis hash is "GENESIS"; each entry hashes `previous_hash|id|timestamp|action|...|level`
- **Module-level stats** — Chat mode pipeline stats use module-level dict in tools.py, avoiding dependency on SDK metadata format parsing

## Known Limitations

- **PII detection gaps** — Regex-based, won't catch unicode obfuscation, zero-width characters, base64-encoded PII, non-US phone formats, or PII in image attachments
- **Prompt injection bypass** — 10 patterns catch common attacks but may miss indirect injection, multi-language, semantic injection, or payload in subject line; redaction wall bounds damage
- **Token.json plaintext** — OAuth token stored unencrypted on disk; theft grants read-only Gmail access
- **No key rotation** — SQLCipher encryption key doesn't rotate; stored in plaintext environment variable
- **USD-only** — Currency parsing assumes US dollars; international formats not supported

> See [WHAT_COULD_BREAK.md](docs/WHAT_COULD_BREAK.md) for comprehensive failure mode analysis and production readiness gaps.

## Documentation

| File | Description |
|------|-------------|
| [Sample Outputs](docs/sample_outputs/) | Example command outputs from real Gmail inbox |
| [WHAT_COULD_BREAK.md](docs/WHAT_COULD_BREAK.md) | Failure mode analysis, attack scenarios, production gaps |
| [CLI_COMMANDS.md](CLI_COMMANDS.md) | Complete command reference with all flags |
| [IMPROVEMENTS_SUMMARY.md](IMPROVEMENTS_SUMMARY.md) | Email filtering and accuracy improvements |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Development context for resuming work |

## Tech Stack

- **Agent Framework:** OpenAI Agents SDK (`openai-agents`)
- **MCP Server:** FastMCP (`mcp[cli]`)
- **Gmail API:** `google-api-python-client`
- **PII Detection:** Presidio + spaCy (`en_core_web_sm`)
- **Encrypted DB:** SQLCipher (`pysqlcipher3`) with graceful fallback to `sqlite3`
- **LLM Providers:** OpenAI (`openai`) or Anthropic (`anthropic`)
- **Console Display:** Rich library
- **Testing:** pytest (183 tests)

# PROJECT_CONTEXT.md — Secure Personal Finance Monitor

> **Purpose:** Load this file into a fresh Claude Code session to resume development.
> Say: "Read PROJECT_CONTEXT.md and continue building" to pick up where things left off.

---

## Current Status (February 2026)

✅ **COMPLETE** — All 7 phases finished, 183 tests passing, documentation updated.

**Major Components:**
- 6-layer security pipeline (MCP, Blocklist, PII Redaction, Agent, Storage, Audit)
- Chat mode with real-time pipeline stats and natural language queries
- Sample outputs documentation with real Gmail examples
- Comprehensive failure mode analysis (docs/WHAT_COULD_BREAK.md)
- Professional README without assessment references

**Known Limitations:** See [docs/WHAT_COULD_BREAK.md](docs/WHAT_COULD_BREAK.md) for failure modes and production gaps.

### Recent Updates (February 2026)

**MCP Architecture Refactor** ✅ COMPLETE
- **Issue**: Agent was bypassing MCP protocol by directly importing Python functions from MCP server
- **Fix**: Full MCP client-server architecture with stdio transport
  - Agent connects via `MCPServerStdio` with 60-second timeout for large email batches
  - MCP server runs full security pipeline (blocklist → PII redaction → extraction)
  - Returns ONLY sanitized transaction data as JSON
  - Scan mode calls MCP tools directly via `mcp_client.call_tool()`
  - Chat mode extracts pipeline stats from `run_result.new_items`
- **Result**: Proper protocol separation, pipeline stats display correctly in chat mode
- **Files Modified**: [src/main.py](src/main.py), [src/agent/finance_agent.py](src/agent/finance_agent.py), [src/mcp_server/\_\_main\_\_.py](src/mcp_server/__main__.py), [src/mcp_server/server.py](src/mcp_server/server.py)

---

## Project Overview

An agentic AI system that monitors personal finances via Gmail while ensuring PII never reaches the LLM. Built for the **Cequence AI internship assessment**.

**Data Flow:** Gmail API (raw, dangerous) → PII Redactor (no LLM) → Sanitized Data (safe) → AI Agent → Encrypted DB + Audit Log

---

## Tech Stack (DO NOT change)

| Component | Package | Purpose |
|-----------|---------|---------|
| Agent Framework | `openai-agents` | Agent orchestration with `Agent`, `Runner.run_sync`, `function_tool` |
| MCP Server | `mcp[cli]` (FastMCP) | Gmail integration via Model Context Protocol |
| Gmail API | `google-api-python-client` | Read-only email access |
| PII Detection | `presidio-analyzer` + `presidio-anonymizer` + `spacy` | NER-based PII detection |
| Regex Patterns | `re` (stdlib) | Deterministic PII pattern matching |
| Encrypted DB | `pysqlcipher3` | SQLCipher-encrypted SQLite (graceful fallback to plain sqlite3) |
| LLM (OpenAI) | `openai` (via agents SDK) | Transaction categorization |
| LLM (Anthropic) | `anthropic` | Alternative LLM backend |
| Config | `python-dotenv` | Environment variable management |
| Console | `rich` | Formatted terminal output |
| Testing | `pytest` | Test framework |

**Note:** `pysqlcipher3` requires Homebrew `sqlcipher` on macOS (`brew install sqlcipher`).

---

## Full Project Structure

```
secure-finance-monitor/
├── .env.example              # Env var template (OPENAI_API_KEY, DB_ENCRYPTION_KEY, etc.)
├── .gitignore                # Ignores secrets, DB files, caches, token.json
├── requirements.txt          # All Python dependencies (13 packages)
├── README.md                 # Full project documentation with architecture diagram
├── PROJECT_CONTEXT.md        # This file — session resumption context
├── SECURITY_DESIGN.md        # [NOT YET CREATED — Phase 7]
├── src/
│   ├── __init__.py
│   ├── main.py               # CLI entry point [PLACEHOLDER — needs Phase 5 integration]
│   ├── redactor/
│   │   ├── __init__.py
│   │   ├── patterns.py       # 10 PII regex patterns as PIIPattern dataclasses, priority-ordered
│   │   ├── pii_redactor.py   # 3-pass pipeline: regex → Presidio NER → validation. Fail-closed.
│   │   └── validator.py      # Post-redaction safety net — scans for leaked PII-like sequences
│   ├── mcp_server/
│   │   ├── __init__.py
│   │   ├── __main__.py       # python -m src.mcp_server
│   │   ├── gmail_auth.py     # OAuth2 flow (gmail.readonly scope ONLY)
│   │   ├── gmail_auth_runner.py  # Standalone auth script
│   │   ├── gmail_client.py   # Gmail API wrapper (search, fetch body, parse MIME)
│   │   └── server.py         # FastMCP server with 3 tools, singleton PIIRedactor, fail-closed
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── finance_agent.py  # FinanceAgent class: run_scan(), chat(), sanitize_response()
│   │   ├── llm_backend.py    # LLM abstraction: OpenAIBackend, AnthropicBackend, MockBackend
│   │   ├── prompts.py        # 4 security-hardened system prompts (8 security rules each)
│   │   └── tools.py          # 5 @function_tool tools + 10-pattern injection detector
│   └── storage/
│       ├── __init__.py
│       ├── models.py          # 4 dataclasses: Transaction, Subscription, Anomaly, AuditEntry
│       ├── database.py        # EncryptedDatabase: sqlcipher + sqlite3 fallback, CRUD, analytics
│       └── audit.py           # AuditLogger: SHA-256 hash chain, dual write (DB + JSONL), verify_integrity()
├── tests/
│   ├── test_redactor.py       # 59 tests — PII patterns, preservation, sample emails, edge cases
│   ├── test_mcp_server.py     # 25 tests — redacted output, fail-closed, query builder, extraction
│   ├── test_agent.py          # 48 tests — prompt security, injection patterns, categorization, sanitizer
│   ├── test_storage.py        # 42 tests — encryption, CRUD, batch, analytics, hash chain, tamper detection
│   └── test_prompt_injection.py  # [NOT YET CREATED — Phase 6]
└── demo/
    ├── sample_emails.json     # 10 realistic fake financial emails (incl. 1 prompt injection)
    └── injection_emails.json  # [NOT YET CREATED — Phase 6]
```

---

## Architecture

```
Gmail API (raw, dangerous)
    │
    ▼
┌──────────────────────────┐
│  SECURITY WALL            │
│  Pass 1: Regex (10 types) │
│  Pass 2: Presidio NER     │
│  Pass 3: Validator sweep   │
│  FAIL CLOSED              │
└──────────────────────────┘
    │
    ▼ (sanitized — no PII)
┌──────────────────────────┐
│  AI AGENT                 │
│  OpenAI Agents SDK        │
│  5 function tools         │
│  Injection detection      │
│  Output also sanitized    │
└──────────────────────────┘
    │
    ├──▶ Encrypted DB (SQLCipher) — metadata ONLY, no raw content
    └──▶ Audit Log — hash-chained, tamper-evident, dual write
```

---

## 10 Security Rules (NEVER violate)

1. **PII redaction before LLM** — 3-pass pipeline runs before any LLM call
2. **Fail closed** — if redaction fails, content is withheld (never returned raw)
3. **Agent output post-scanned** — response sanitizer re-scans through PIIRedactor
4. **Gmail read-only** — scope locked to `gmail.readonly`
5. **No raw storage** — raw email content never stored; process in memory, then discard (`del` after use)
6. **Prompt injection detection** — 10 patterns scanned, flagged as CRITICAL
7. **Hash-chained audit** — SHA-256 chain, tamper = chain breaks
8. **Encrypted at rest** — SQLCipher encryption (fallback to SQLite for demo)
9. **Dual audit logging** — both encrypted DB and JSONL file
10. **CRITICAL to stderr** — security events printed to stderr via rich

---

## Phase-by-Phase Status

### Phase 0: Project Setup — COMPLETE
- Directory structure, requirements.txt, .env.example, .gitignore
- `demo/sample_emails.json` — 10 emails: 3 Chase, 2 PayPal, 2 Amazon, 1 Netflix, 1 Venmo, 1 injection (msg-010)
- All dependencies installed, spacy `en_core_web_sm` model downloaded

### Phase 1: PII Redaction Layer — COMPLETE (59 tests)
- `patterns.py` — 10 PII patterns: CREDIT_CARD(10), MASKED_CARD(5), SSN(20), ROUTING_NUMBER(25), ACCOUNT_NUMBER(30), GENERIC_LONG_NUMBER(35), PHONE_NUMBER(40), SECURE_URL(45), EMAIL_ADDRESS(50), ADDRESS(55)
- `pii_redactor.py` — 3-pass pipeline (regex → Presidio → validation), `RedactionResult` dataclass, fail-closed safety fallback
- `validator.py` — leak pattern scanner with safe-context detection (dollar amounts, dates, redaction tags, ZIP codes)
- Credit card handling: last 4 preserved → `[CARD_****4892]`
- Dollar amounts and merchant names pass through (agent needs them)

### Phase 2: Gmail MCP Server — COMPLETE (25 tests)
- `gmail_auth.py` — OAuth2 with `gmail.readonly` scope
- `gmail_client.py` — `GmailClient`: search_emails, get_email_body, build_financial_query (17 default senders)
- `server.py` — FastMCP with 3 `@mcp.tool()`: fetch_financial_emails, get_email_detail, get_financial_summary
- Singleton `_redactor` instance, `_redact_email_body()` with fail-closed RuntimeError
- `_infer_category()` — keyword-based with 9 categories

### Phase 3: AI Agent — COMPLETE (48 tests)
- `prompts.py` — 4 prompts: FINANCE_AGENT_SYSTEM_PROMPT (8 security rules, 12 categories), CATEGORIZATION, ANOMALY_DETECTION, WEEKLY_SUMMARY
- `tools.py` — 5 `@function_tool` tools + `check_prompt_injection_raw()` with 10 injection patterns
- `llm_backend.py` — `LLMBackend` ABC → OpenAIBackend, AnthropicBackend, MockBackend; auto-detection
- `finance_agent.py` — `FinanceAgent`: run_scan (full pipeline), chat (Runner.run_sync, max_turns=5), sanitize_response (defense in depth)
- `ScanResult` dataclass: transactions, anomalies, summary, security_flags, audit_log

### Phase 4: Encrypted Storage + Audit — COMPLETE (42 tests)
- `models.py` — 4 dataclasses: Transaction, Subscription, Anomaly, AuditEntry (all with to_dict/from_dict)
- `database.py` — `EncryptedDatabase`: pysqlcipher3 + sqlite3 fallback, 4-table schema, CRUD, batch save, upsert subscriptions, stale detection, analytics (spending by category, trends, merchant history), verify_encryption
- `audit.py` — `AuditLogger`: SHA-256 hash chain (GENESIS seed), dual write (DB + JSONL), verify_integrity(), convenience loggers (scan_start, email_processed, categorization, anomaly_detected, response_sent, security_event), CRITICAL → stderr

### Phase 5: Integration — COMPLETE
- CLI with 11 subcommands: `scan`, `chat`, `demo`, `demo-injection`, `summary`, `anomalies`, `subscriptions`, `audit`, `verify`, `test-gmail`, `reset`
- 9-stage security pipeline display using Rich library (Tree, Panel, Table)
- Email blocklist system with configurable filters (`config/blocklist.json`)
- Progressive output with delays between pipeline stages for live demo
- File logging to `logs/` directory (DEBUG level), clean console output (ERROR level)
- Connected: Gmail MCP → Blocklist → PII Redactor → Agent → Storage → Audit → Display

### Phase 6: Demo Data + Injection Tests — NOT STARTED
- Create `demo/injection_emails.json` with diverse injection payloads
- Create `tests/test_prompt_injection.py` with dedicated injection test suite
- Ensure all injection attempts are caught and logged as CRITICAL

### Phase 7: Security Design Document — NOT STARTED
- Create `SECURITY_DESIGN.md` — detailed security architecture document
- Threat model, defense layers, data flow security analysis

---

## Recent Improvements (Feb 2026)

### Chat Mode Enhancement
**Problem:** Chat agent wasn't calling `scan_financial_emails` when users asked about transactions, causing:
- "Fetched: 0" metadata display (no tool called)
- Only returning 1 stale transaction from database
- Missing all recent Gmail data

**Root Causes:**
1. Ambiguous prompt - only mentioned calling tool for "emails", not "transactions/spending"
2. Default `max_results=20` instead of 100
3. Missing `total_redactions` field in tool return value
4. Silent exception handling in metadata extraction

**Fixes Applied:**
1. **Rewrote system prompt** ([src/agent/prompts.py](src/agent/prompts.py:28-43)) - Added "CRITICAL RULE - ALWAYS FETCH FRESH DATA" with explicit examples showing every finance query must call `scan_financial_emails` first
2. **Increased tool defaults** ([src/agent/tools.py](src/agent/tools.py:35)) - Changed from `max_results=20` to `max_results=100` to match scan command
3. **Pass through redaction count** ([src/agent/tools.py](src/agent/tools.py:52-53,106)) - Added `total_redactions` to tool return value
4. **Robust metadata extraction** ([src/agent/finance_agent.py](src/agent/finance_agent.py:237-285)) - Enhanced to check multiple result locations (step.tool_results, tool_call.result, step.output), handle dict/string formats, explicit None checks, log warnings instead of silent failures

**Result:** Chat mode now correctly fetches fresh Gmail data for every query, returns all 16 transactions, and displays accurate pipeline stats.

### Demo Output Improvements
**Fixes:**
1. **Demo-injection formatting** ([src/main.py](src/main.py:441-543)) - Replaced raw prints with rich Tree structure (4 layers: Email Processing, Injection Detection, Security Threats, Audit Trail), removed inline CRITICAL stderr spam
2. **PII Redaction Demo** ([src/mcp_server/server.py](src/mcp_server/server.py:138-177)) - Fixed HTML stripping position bug (strip BEFORE calculating positions), added ellipsis formatting, only use examples where before != after
3. **CRITICAL event suppression** ([src/storage/audit.py](src/storage/audit.py:29-37,95-96)) - Added `suppress_stderr` parameter to suppress CRITICAL stderr output during scan/demo modes (still logged to file and displayed in LAYER 4/6)

### Chat Mode Capabilities
Users can now ask natural language queries:
- **Transaction queries:** "last 30 days transactions", "what did I buy this week"
- **Spending analysis:** "give me a spending summary", "how much did I spend on groceries"
- **Merchant analysis:** "which merchants did I pay the most", "show duplicate charges"
- **Security:** "any suspicious transactions", "find unusual spending"

All queries now fetch fresh Gmail data with proper pipeline stats display.

---

## Key Design Decisions

1. **Pattern priority ordering** — GENERIC_LONG_NUMBER at priority 35 (before PHONE at 40) so order numbers like `#114-3948572-8837261` are caught by context-aware pattern first
2. **Presidio filtering** — Presidio results skip DATE_TIME, URL entities, and already-redacted `[..._REDACTED]` spans to avoid double-redaction
3. **Validator safe contexts** — Dollar amounts (`$1,234.56`), dates, redaction tags, store numbers, ZIP codes are all whitelisted
4. **SQLCipher row format** — When encrypted, `row_factory` is None (returns tuples); all `_row_to_*` helpers handle both tuple and Row formats
5. **Subscription upsert** — Same merchant + amount → update `last_seen` instead of duplicating
6. **LLM auto-detection** — Check OPENAI_API_KEY → ANTHROPIC_API_KEY → fall back to MockBackend
7. **Audit hash chain** — Genesis hash is string "GENESIS"; each entry hashes `previous_hash|id|timestamp|action|tool_used|details|redactions|security_flags|level`
8. **Patch paths in tests** — `fetch_financial_emails` must be patched at `src.mcp_server.server.fetch_financial_emails` (where it's defined), not at the import site

---

## How to Run Tests

```bash
# All 183 tests
python -m pytest tests/ -v

# By phase
python -m pytest tests/test_redactor.py -v      # Phase 1: 59 tests
python -m pytest tests/test_mcp_server.py -v     # Phase 2: 25 tests
python -m pytest tests/test_agent.py -v          # Phase 3: 48 tests
python -m pytest tests/test_storage.py -v        # Phase 4: 42 tests
python -m pytest tests/test_integration.py -v    # Integration: 9 tests
```

## How to Demo

```bash
# Demo mode (no API keys needed — uses MockBackend)
python -m src.main demo

# Full Gmail scan (requires OAuth setup + API key)
python -m src.main scan --days 30 --max-results 50

# Interactive chat
python -m src.main chat
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | No* | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | No* | — | Anthropic API key (alternative) |
| `MODEL_PROVIDER` | No | auto-detect | `openai`, `anthropic`, or `mock` |
| `MODEL_NAME` | No | `gpt-4o-mini` | LLM model name |
| `AGENT_MODEL` | No | `gpt-4o-mini` | Agent orchestration model |
| `GOOGLE_CREDENTIALS_PATH` | For Gmail | `./credentials.json` | Google OAuth credentials |
| `GOOGLE_TOKEN_PATH` | For Gmail | `./token.json` | Cached OAuth token |
| `DB_ENCRYPTION_KEY` | Recommended | — | SQLCipher encryption key |
| `DB_PATH` | No | `finance_monitor.db` | Database file path |
| `SCAN_DAYS` | No | `30` | Default scan lookback |
| `MAX_EMAILS_PER_SCAN` | No | `100` | Max emails per scan |

*Falls back to MockBackend if no API key set — full pipeline still works for demo.

---

## Known Issues / TODOs

1. **Chat metadata display** - Pipeline stats sometimes show "Fetched: 0" due to OpenAI Agents SDK result format variations. Enhanced metadata extraction checks multiple locations but may need further refinement.
2. **datetime.utcnow() deprecation** - Python 3.12+ prefers `datetime.now(datetime.UTC)`. Cosmetic only, does not affect functionality. Low priority.
3. **SQLCipher dependency** - Requires system-level `sqlcipher` library (`brew install sqlcipher` on macOS). Graceful fallback to plain sqlite3 if unavailable.
4. **Presidio spacy model** - `en_core_web_sm` must be downloaded separately: `python -m spacy download en_core_web_sm`
5. **Test count update** - README and docs reference 174 tests, but current count is 183 after recent improvements.

---

## Resume Instructions

To continue building, the next phases are:

1. **Phase 5 — Integration:** Wire `main.py` with CLI subcommands (demo, scan, chat). Connect Gmail → Redactor → Agent → Storage → Audit end-to-end.
2. **Phase 6 — Injection Tests:** Create `demo/injection_emails.json` and `tests/test_prompt_injection.py`.
3. **Phase 7 — Security Doc:** Create `SECURITY_DESIGN.md`.

All existing code is tested and passing (174 tests). No breaking changes should be introduced.

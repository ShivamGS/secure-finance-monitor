# System Design: MCP Architecture

Comprehensive design document for the Secure Finance Monitor's MCP-based security architecture.

---

## Architecture Overview

The system uses **MCP (Model Context Protocol)** to enforce a security boundary between raw Gmail data and the AI agent. All sensitive operations (Gmail API access, PII redaction, transaction extraction) happen **inside the MCP server**. The agent only receives sanitized transaction metadata.

### Key Principle

**The MCP server IS the security boundary. Everything that comes out of it is sanitized.**

---

## Two Execution Modes

### 1. Scan Mode (Direct MCP)
Batch processing for extracting and storing transactions from Gmail.

```
User Command
    ↓
main.py:cmd_scan
    ↓ (Creates MCP client)
MCP Client ──call_tool("fetch_financial_emails")──> MCP Server Process
                                                        │
                                                    [Security Pipeline]
                                                        │
                                                    1. Gmail API
                                                    2. Blocklist
                                                    3. PII Redaction (3-pass)
                                                    4. Transaction Extraction
                                                        │
MCP Client <─────────────────────────────────────  Sanitized JSON
    ↓
Storage (Database + Audit)
    ↓
Display (Rich console output)
```

**Flow:** `main.py` → MCP client → `fetch_financial_emails` → security pipeline → JSON → storage → display

**No LLM needed** — extraction is regex-based, happens in MCP server.

### 2. Chat Mode (Agent + MCP)
Interactive natural language interface powered by OpenAI Agents SDK.

```
User Query
    ↓
main.py:cmd_chat
    ↓
FinanceAgent (OpenAI Agents SDK)
    │
    │ [Agent decides which tool to call]
    │
    ├──call_tool("fetch_financial_emails")──> MCP Server
    ├──call_tool("get_financial_summary")───> MCP Server
    └──call_tool("get_email_detail")────────> MCP Server
                                                  │
                                              [Security Pipeline]
                                                  │
                                              1. Gmail API
                                              2. Blocklist
                                              3. PII Redaction (3-pass)
                                              4. Transaction Extraction
                                                  │
Agent <───────────────────────────────────── Sanitized JSON
    │
    │ [Agent analyzes data, calls local tools]
    │
    ├─ categorize_transaction(merchant, amount)
    ├─ detect_anomalies(transactions)
    └─ check_prompt_injection(text)
    │
    └──> Natural language response
             │
         Output re-scan (PII check)
             │
         Display to user
```

**Flow:** `main.py` → Agent → MCP tools → security pipeline → JSON → agent processing → output sanitization → display

**LLM used** — agent interprets query, analyzes transactions, generates natural language response.

---

## MCP Security Pipeline

All MCP tools (`fetch_financial_emails`, `get_financial_summary`, `get_email_detail`) run the same security pipeline inside the MCP server process:

### Layer 1: Gmail API
- **OAuth 2.0** authentication with `gmail.readonly` scope
- **Read-only** access (cannot delete, modify, or send emails)
- **Financial sender query**: `from:(paypal OR walmart OR amazon OR visa OR discover OR venmo)`
- Returns raw email objects (id, sender, subject, date, body)

### Layer 2: Email Blocklist
- **Pre-filters** promotional/spam emails before redaction
- **Checks:** sender domains, sender emails, subject patterns
- **Example blocks:** `marketing.ulta.com`, `deals@groupon.com`, "flash sale"
- **Action:** Skipped emails never reach redaction (efficiency)
- **Stats:** Blocked count included in pipeline_stats

### Layer 3: PII Redaction Wall (3-Pass)

**Pass 1: Regex Patterns (10 patterns)**
- Credit cards: `4532-8821-7744-3847` → `[CARD_****3847]`
- SSN: `123-45-6789` → `[SSN_REDACTED]`
- Phone numbers: `(555) 123-4567` → `[PHONE_REDACTED]`
- Email addresses: `user@example.com` → `[EMAIL_REDACTED]`
- Physical addresses: `123 Main St, SF CA 94102` → `[ADDRESS_REDACTED]`
- Account numbers: `Account #12345678` → `[ACCT_REDACTED]`
- Routing numbers: `021000021` → `[ROUTING_REDACTED]`
- Secure URLs: `https://secure.bank.com/verify?token=abc` → `[SECURE_URL_REDACTED]`
- **Preserves:** Dollar amounts, merchant names, dates, redaction tags

**Pass 2: Presidio NER (ML-based)**
- Uses spaCy `en_core_web_sm` model
- Detects: PERSON, LOCATION, NRP, MEDICAL_LICENSE, CREDIT_CARD, US_SSN
- **Skips:** DATE_TIME, URL, already-redacted spans (avoid double-redaction)
- Fallback: If Presidio fails, continues with regex-only results

**Pass 3: Validation Sweep**
- Scans for leaked numeric sequences (7+ contiguous digits)
- **Whitelist:** Dollar amounts, dates, ZIP codes, store numbers, redaction tags
- **Action:** If suspicious number found → FAIL CLOSED (content withheld)

**Fail-Closed Design:**
- Any redaction error → email skipped, content withheld
- Audit log records: `[REDACTION_FAILED: content withheld]`
- **No PII leaks** even on failure

### Layer 4: Transaction Extraction (Regex-Based)

**Step 1: Promotional Filter**
- Checks subject and body for 50+ promotional patterns
- Examples: "sale", "offer", "discount", "unsubscribe", "job alert"
- **Action:** Skip promotional emails (not transactions)

**Step 2: Merchant Extraction**
- Try sender name: `"Walmart <no-reply@walmart.com>"` → `"Walmart"`
- Try subject: `"Receipt from PayPal"` → `"PayPal"`
- Fallback: email domain → `"walmart.com"` → `"Walmart"`

**Step 3: Amount Extraction**
- Regex: `\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)`
- Extract all amounts, take MAX (handles subtotal, tax, total)
- Filter: $0.01 to $999,999 (reasonable transaction range)

**Step 4: Date Extraction**
- Try email body: `"Date: Feb 10, 2026"` → `2026-02-10`
- Fallback: email Date header → normalized to `YYYY-MM-DD`

**Step 5: Payment Method Extraction**
- Detect: "Visa ending in 1234", "Apple Pay", "PayPal"
- Returns: `visa`, `discover`, `apple_pay`, `paypal`, etc.

**Step 6: Confirmation Keyword Check**
- High-value transactions (>$500) require confirmation keywords
- Examples: "you purchased", "order confirmed", "receipt for your"
- **Action:** Skip promotional offers (e.g., "Book for $3000" without confirmation)

**Output:**
```json
{
  "transactions": [
    {
      "email_id": "187abc123",
      "merchant": "Walmart",
      "amount": 39.88,
      "date": "2026-02-10",
      "payment_method_type": "visa"
    }
  ],
  "pipeline_stats": {
    "fetched": 100,
    "blocked": 20,
    "redacted": 326,
    "injections": 0,
    "extracted": 80
  }
}
```

---

## Security Boundaries

### Boundary 1: MCP Server Process Isolation
- MCP server runs as **subprocess** (started by MCP client)
- Communicates via **stdin/stdout** (stdio transport)
- **No shared memory** with parent process
- **Environment inherited** from parent (includes `.env` variables)

### Boundary 2: Agent <-> MCP Tools
- Agent **cannot** call Gmail API directly
- Agent **cannot** access raw email bodies
- Agent **only** receives JSON from MCP tools
- **All PII removed** before JSON reaches agent

### Boundary 3: Output Re-Scanning
- Agent responses re-scanned by PIIRedactor before display
- Catches: Hallucinated PII, leaked redaction tags
- **Logged:** `✅ Response verified (no PII leaked)`

---

## Data Flow Comparison

| Aspect | Scan Mode | Chat Mode |
|--------|-----------|-----------|
| **Entry point** | `main.py:cmd_scan` | `main.py:cmd_chat` |
| **MCP client** | Direct MCPServerStdio call | Via Agent.mcp_servers |
| **MCP tool called** | `fetch_financial_emails` | `fetch_financial_emails` OR `get_financial_summary` |
| **Security pipeline** | Same (Gmail → Blocklist → Redaction → Extraction) | Same |
| **LLM used** | ❌ No (regex extraction only) | ✅ Yes (OpenAI Agents SDK) |
| **Local tools** | ❌ None | ✅ `categorize_transaction`, `detect_anomalies`, `check_prompt_injection` |
| **Output format** | Rich console table | Natural language response |
| **Output scanning** | ❌ Not needed (no LLM) | ✅ PIIRedactor re-scan |
| **Storage** | Direct to DB | Direct to DB |
| **Audit logging** | Every email processed | Every email processed + every response |

---

## MCP Tools Reference

### 1. `fetch_financial_emails(days, max_results)`
**Purpose:** Fetch and extract transactions from Gmail financial emails

**Parameters:**
- `days` (int): Lookback period (default: 30, **NOT CAPPED** ⚠️)
- `max_results` (int): Max emails to fetch (capped at 100)

**Returns:**
```json
{
  "transactions": [...],
  "pipeline_stats": {
    "fetched": 100,
    "blocked": 20,
    "redacted": 326,
    "injections": 0,
    "extracted": 80
  },
  "query_days": 30
}
```

**Used by:** Scan mode, Chat mode (when agent needs transaction list)

### 2. `get_financial_summary(days)`
**Purpose:** Get categorized spending summary

**Parameters:**
- `days` (int): Lookback period (default: 30, **NOT CAPPED** ⚠️)

**Returns:**
```json
{
  "transactions": [...],  // Same as fetch_financial_emails
  "total_transactions": 80,
  "pipeline_stats": {...},
  "query_days": 30
}
```

**Used by:** Chat mode (when agent needs summary, not full transaction list)

### 3. `get_email_detail(email_id)`
**Purpose:** Get redacted details of a specific email

**Parameters:**
- `email_id` (str): Gmail email ID (no format validation ⚠️)

**Returns:**
```json
{
  "email_id": "187abc123",
  "sender": "Walmart <no-reply@walmart.com>",
  "subject": "Your Walmart.com order",
  "date": "2026-02-10",
  "body": "[REDACTED BODY]",
  "redacted": true,
  "redaction_count": 12
}
```

**Used by:** Chat mode (when agent needs to examine specific email)

---

## Agent Tools (Local, Non-MCP)

These tools run **inside the agent process**, not in MCP server. They analyze data that's already been sanitized by MCP.

### 1. `categorize_transaction(merchant, amount, snippet)`
**Purpose:** LLM-based categorization of transaction
**Returns:** `Groceries`, `Dining`, `Travel`, `Shopping`, `Utilities`, `Entertainment`, `Other`

### 2. `detect_anomalies(transactions_json)`
**Purpose:** Detect suspicious patterns
**Returns:** List of anomalies: `DUPLICATE`, `SPIKE`, `NEW_MERCHANT`, `FREQUENCY`, `SECURITY`

### 3. `check_prompt_injection(text)`
**Purpose:** Scan text for 10 injection patterns
**Returns:** `True` if injection detected, `False` otherwise

---

## Failure Modes

### MCP Server Crashes
**Symptoms:** Chat/scan fails with "MCP server connection error"
**Causes:** Gmail API failure, Python exception in redaction, memory exhaustion
**Impact:** Availability only (no security breach)
**Mitigation needed:** Process supervision, auto-restart

### MCP Tool Timeout (60 seconds)
**Symptoms:** "Timed out waiting for MCP response"
**Causes:** Large email batch (100 emails), Gmail API rate limit, Presidio slow processing
**Impact:** Operation fails, no partial results
**Mitigation needed:** Configurable timeout, progress streaming

### MCP Tool Parameter Abuse
**Risk:** Agent calls `fetch_financial_emails(days=36500)` (100 years)
**Impact:** Gmail quota exhaustion, timeout, DoS
**Current protection:** `max_results` capped at 100 ✅, `days` NOT capped ❌
**Mitigation needed:** Cap `days` to 365 max inside MCP server

### MCP Server Code Compromise
**Risk:** Attacker modifies `src/mcp_server/server.py`
**Impact:** **CRITICAL** — entire security boundary collapses
**Current protection:** File permissions (OS level only)
**Mitigation needed:** Code signing, hash verification, container isolation

---

## Configuration

### MCP Client (Scan Mode)
```python
mcp_client = MCPServerStdio(
    params=MCPServerStdioParams(
        command="python",
        args=["-m", "src.mcp_server"],
        cwd=os.getcwd(),
        env=os.environ.copy(),
        encoding="utf-8",
    ),
    name="SecureFinanceMonitor",
    client_session_timeout_seconds=60.0,  # 60s timeout for large batches
)
```

### MCP Client (Chat Mode via Agent)
```python
self.mcp_server = MCPServerStdio(
    params=MCPServerStdioParams(
        command="python",
        args=["-m", "src.mcp_server"],
        cwd=os.getcwd(),
        env=os.environ.copy(),
        encoding="utf-8",
    ),
    name="SecureFinanceMonitor",
    client_session_timeout_seconds=60.0,
)

self.agent = Agent(
    name="SecureFinanceAgent",
    instructions=SYSTEM_PROMPT,
    mcp_servers=[self.mcp_server],  # Auto-discovers MCP tools
    tools=[categorize_transaction, detect_anomalies, check_prompt_injection],
)
```

---

## Module Responsibilities

| Module | Responsibility | Location |
|--------|---------------|----------|
| **main.py** | CLI entry point, command routing | Root |
| **mcp_server/server.py** | FastMCP server, security pipeline orchestration | MCP server process |
| **mcp_server/gmail_client.py** | Gmail API wrapper, OAuth handling | MCP server process |
| **config/blocklist.py** | Email filtering (spam, promo) | MCP server process |
| **redactor/pii_redactor.py** | 3-pass PII redaction pipeline | MCP server process |
| **redactor/patterns.py** | Regex patterns for PII detection | MCP server process |
| **redactor/validator.py** | Post-redaction validation sweep | MCP server process |
| **agent/extractor.py** | Transaction extraction (regex) | MCP server process (imported) |
| **agent/finance_agent.py** | OpenAI Agents SDK wrapper, MCP client | Agent process |
| **agent/tools.py** | Local agent tools (categorize, detect anomalies) | Agent process |
| **agent/prompts.py** | System prompts for agent | Agent process |
| **storage/database.py** | SQLCipher database operations | Both processes |
| **storage/audit.py** | Hash-chained audit logging | Both processes |
| **display.py** | Rich console visualization | Main process |

---

## Key Design Decisions

### Why MCP?
- **Security boundary enforcement** — Agent physically cannot access raw emails
- **Process isolation** — MCP server crashes don't crash agent
- **Scalability** — Can run MCP server remotely, add authentication, rate limiting
- **Testability** — Can test MCP tools independently of agent

### Why Fail-Closed?
- **Conservative security** — Better to skip email than leak PII
- **Audit trail** — All failures logged with `[REDACTION_FAILED]`
- **Graceful degradation** — Missing one email better than exposing all PII

### Why 60-Second Timeout?
- **Large batches** — 100 emails × 50+ redaction patterns × Presidio NER = significant processing time
- **Gmail API latency** — Network delays, rate limiting add seconds
- **Default 5s too short** — Frequent timeouts in production testing

### Why No Days Cap?
- **Oversight** — Originally designed for 30-day scans, forgot to add validation
- **Production gap** — Identified in security review, flagged for fix
- **Mitigation** — Add server-side validation: `if days > 365: raise ValueError`

---

## Summary

**Security model:** MCP server is the trust boundary. All raw data processing (Gmail API, blocklist, redaction, extraction) happens inside. Agent only receives sanitized JSON.

**Two modes, one pipeline:** Scan and chat use identical security pipeline, differ only in presentation (batch table vs natural language).

**Defense-in-depth:** 6 layers (MCP, Blocklist, Redaction, Agent, Storage, Audit), fail-closed design, output re-scanning.

**Known gaps:** Days parameter not capped, no MCP code integrity checks, no unicode normalization in PII patterns, no external audit anchor.

**Production readiness:** Add parameter validation, process supervision, hash verification, unicode normalization for production deployment.

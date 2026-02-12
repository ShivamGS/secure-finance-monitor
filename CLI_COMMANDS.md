# Secure Finance Monitor - CLI Commands Reference

All commands use the format: `python -m src.main <command> [options]`

---

## Core Commands

### 1. `scan` - Run Gmail Financial Scan
**Purpose**: Fetch financial emails from Gmail, extract transactions, detect anomalies

```bash
python -m src.main scan                    # Scan last 30 days (default)
python -m src.main scan --days 7           # Scan last 7 days
python -m src.main scan --days 30 --max-results 50  # Scan last 30 days, max 50 emails
python -m src.main scan --fresh            # Clear database before scanning
```

**What it does**:
- Connects to Gmail via OAuth
- Fetches financial emails (receipts, transactions, etc.)
- Redacts PII (credit cards, SSNs, account numbers)
- Extracts: merchant, amount, date, payment method
- Categorizes transactions (Groceries, Dining, Travel, etc.)
- Detects anomalies (duplicates, unusual amounts)
- Saves to encrypted database
- Logs all actions to audit trail

**Output**: Table of transactions with spending breakdown by category

---

### 2. `chat` - Interactive Chat Mode
**Purpose**: Ask natural language questions about your finances

```bash
python -m src.main chat
```

**Example queries**:
- "What did I spend on groceries this week?"
- "Show my last 10 transactions"
- "How much did I spend at Amazon this month?"
- "Do I have any duplicate charges?"

**What it does**:
- Uses OpenAI Agents SDK to understand your questions
- Calls `scan_financial_emails` tool to fetch data
- Analyzes and responds with structured JSON or natural language
- All responses sanitized for PII

**Exit**: Type `quit`, `exit`, or press Ctrl+C

---

### 3. `summary` - Generate Financial Summary
**Purpose**: Comprehensive spending report with insights

```bash
python -m src.main summary                 # Last 7 days (default)
python -m src.main summary --days 30       # Last 30 days
```

**What it shows**:
- **All transactions** table (date, merchant, amount, category)
- **Spending by category** with visual bars and percentages
- **Week-over-week comparison** (spending increase/decrease)
- **Active subscriptions** detected (Netflix, Spotify, etc.)
- **Unresolved anomalies** flagged for review
- **Monthly subscription cost** estimate

**Use case**: Weekly/monthly financial review

---

### 4. `anomalies` - Show Detected Anomalies
**Purpose**: Review suspicious transactions and security alerts

```bash
python -m src.main anomalies
```

**What it shows**:
- **DUPLICATE**: Same merchant + same amount within 24 hours
- **SPIKE**: Transaction 3x higher than usual for that merchant
- **NEW_MERCHANT**: First-ever transaction from this merchant
- **FREQUENCY**: Unusually high transactions in one day
- **SECURITY**: Prompt injection or suspicious patterns detected

**Each anomaly includes**:
- Type and severity (low/medium/high/critical)
- Description and recommended action
- Transaction IDs involved

---

### 5. `subscriptions` - List Active Subscriptions
**Purpose**: Track recurring charges

```bash
python -m src.main subscriptions
```

**What it shows**:
- Merchant name
- Amount and frequency (monthly/annual)
- Last charge date
- Total monthly subscription cost

**Detected merchants**: Netflix, Spotify, Adobe, Microsoft 365, gym memberships, etc.

---

## Utility Commands

### 6. `demo` - Run Demo Mode (No Gmail Required)
**Purpose**: Test the system with sample data

```bash
python -m src.main demo
```

**What it does**:
- Uses sample emails from `demo/sample_emails.json`
- Processes through full pipeline (redaction, extraction, categorization)
- Uses separate demo database (`demo_finance_monitor.db`)
- Perfect for testing without real Gmail credentials

**Use case**: Demonstrations, testing, development

---

### 7. `audit` - Show Audit Log
**Purpose**: View security audit trail (tamper-evident hash chain)

```bash
python -m src.main audit                   # Last 7 days, 50 entries
python -m src.main audit --days 30         # Last 30 days
python -m src.main audit --limit 100       # Show 100 entries
python -m src.main audit --security        # Show only security events
python -m src.main audit --verify-chain    # Verify hash chain integrity
```

**What it shows**:
- Timestamp of each action
- Event type (SCAN_START, EMAIL_PROCESSED, ANOMALY_DETECTED, etc.)
- Details (redaction count, injection detected, etc.)
- Hash chain verification status

**Use case**: Security compliance, debugging, forensics

---

### 8. `verify` - Verify System Integrity
**Purpose**: Run comprehensive security and integrity checks

```bash
python -m src.main verify
```

**What it checks**:
- ✓ Database encryption status (SQLCipher enabled?)
- ✓ Audit log hash chain integrity (tamper detection)
- ✓ No PII leaked into database (scans all fields)
- ✓ Database statistics (total transactions, anomalies, etc.)

**Exit codes**:
- 0 = All checks passed
- 1 = Integrity issues detected

**Use case**: Pre-deployment checks, security audits

---

### 9. `test-gmail` - Test Gmail Connectivity
**Purpose**: Verify Gmail OAuth setup without processing emails

```bash
python -m src.main test-gmail
```

**What it does**:
1. Checks for `credentials.json` file
2. Checks for `token.json` file
3. Attempts to connect to Gmail API
4. Fetches 1 sample email to verify access
5. Shows sample email metadata (sender, subject, date)

**Use case**: Initial setup, troubleshooting Gmail connection

---

### 10. `reset` - Clear All Data
**Purpose**: Delete database and audit log (⚠️ DESTRUCTIVE)

```bash
python -m src.main reset                   # Prompts for confirmation
python -m src.main reset --force           # Skip confirmation (use with caution!)
```

**What it deletes**:
- `finance_monitor.db` (all transactions, anomalies, subscriptions)
- `audit.jsonl` (entire audit trail)

**⚠️ WARNING**: This action cannot be undone!

**Use case**: Fresh start, testing, clearing demo data

---

## Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# LLM Provider (openai or anthropic or mock)
MODEL_PROVIDER=openai
MODEL_NAME=gpt-4o-mini
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...

# Gmail OAuth
GOOGLE_CREDENTIALS_PATH=./credentials.json
GOOGLE_TOKEN_PATH=./token.json

# Storage
DB_PATH=finance_monitor.db
DB_ENCRYPTION_KEY=your-32-byte-encryption-key  # Optional but recommended
AUDIT_LOG_PATH=audit.jsonl

# Agent behavior
SCAN_DAYS=30
MAX_EMAILS_PER_SCAN=100

# Security
FAIL_CLOSED=true
ENABLE_RESPONSE_SANITIZATION=true
```

---

## Common Workflows

### First-Time Setup
```bash
# 1. Set up Gmail OAuth
python -m src.mcp_server.gmail_auth_runner

# 2. Test connection
python -m src.main test-gmail

# 3. Run first scan
python -m src.main scan --days 7

# 4. View summary
python -m src.main summary
```

### Weekly Review
```bash
# Scan last 7 days
python -m src.main scan --days 7

# Generate summary
python -m src.main summary --days 7

# Check for anomalies
python -m src.main anomalies
```

### Security Audit
```bash
# Verify system integrity
python -m src.main verify

# Check audit log for security events
python -m src.main audit --security --days 30

# Verify hash chain
python -m src.main audit --verify-chain
```

### Development/Testing
```bash
# Run demo mode (no Gmail needed)
python -m src.main demo

# Test with fresh data
python -m src.main reset --force
python -m src.main scan --days 3
```

---

## Exit Codes

- **0**: Success
- **1**: Error (missing credentials, API failure, integrity check failed, etc.)

---

## Logging

All commands log to console with color-coded output:
- **Green**: Success messages
- **Yellow**: Warnings
- **Red**: Errors
- **Cyan**: Informational headers
- **Dim**: Debug/verbose output

To see detailed logs, set:
```bash
export LOG_LEVEL=DEBUG
```

---

## Tips

1. **Start small**: Use `--days 3` for initial scans to avoid processing too many emails
2. **Use --fresh carefully**: It clears all data, including audit trail
3. **Chat mode**: Great for ad-hoc queries without cluttering scan history
4. **Demo mode**: Perfect for presentations without exposing real financial data
5. **Audit verification**: Run `verify` before any compliance review

---

## Need Help?

```bash
python -m src.main --help              # Show all commands
python -m src.main scan --help         # Show scan command options
python -m src.main summary --help      # Show summary command options
```

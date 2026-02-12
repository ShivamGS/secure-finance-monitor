# Scan Command Output

## Command
```bash
python -m src.main scan --days 30
```

## Output

```
╔══════════════════════════════════════════════════════════════ 🔒 Secure Finance Monitor - Security Pipeline Demo ═══════════════════════════════════════════════════════════════╗
║ Scanning last 30 days                                                                                                                                                           ║
║ Max emails: 100                                                                                                                                                                 ║
║ Mode: SCAN                                                                                                                                                                      ║
║ Started: 2026-02-12 09:41:52                                                                                                                                                    ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

📧 LAYER 1: MCP (Model Context Protocol)
├── ✅ Gmail API connected
├── ✅ Fetched 100 financial emails
└── OAuth 2.0 authenticated | Read-only scope

🚫 LAYER 2: Email Blocklist (Pre-Filter)
├── ✅ Blocklist loaded
├── ⚠️  Blocked 21/100 emails (21.0%)
└── Breakdown:
    ├──   • By sender: 1
    └──   • By subject: 20

🔐 LAYER 3: PII Redaction (3-Pass Pipeline)
├── ❌ 23 emails failed redaction (fail-closed)
├── Total redactions: 168
├── Redaction breakdown:
│   ├──   • presidio_PERSON: 49
│   ├──   • presidio_LOCATION: 41
│   ├──   • email_address: 32
│   ├──   • phone_number: 12
│   ├──   • secure_url: 11
│   ├──   • presidio_NRP: 8
│   ├──   • presidio_US_DRIVER_LICENSE: 8
│   ├──   • address: 3
│   ├──   • generic_long_number: 3
│   └──   • presidio_MEDICAL_LICENSE: 1
└── Pipeline: Regex → Presidio NER → Validation

╔═════════════════════════════════════════════════════════════════════════════ 🎯 PII REDACTION DEMO ═════════════════════════════════════════════════════════════════════════════╗
║ ⚠️  BEFORE (Raw Email - 2 PII items detected):                                                                                                                                   ║
║ ...a request, please do not respond to the email.Learn more. See ourPrivacy Policy.Email Marketing, Walmart.com, 850 Cherry Avenue, San Bruno CA 94066© 2026 Walmart. All       ║
║ rights reserved. | What did yo...                                                                                                                                               ║
║                                                                                                                                                                                 ║
║ ✅ AFTER (Redacted - Safe for LLM):                                                                                                                                             ║
║ ...a request, please do not respond to the email.Learn more. See ourPrivacy Policy.[PERSON_REDACTED] Marketing, Walmart.com, [ADDRESS_REDACTED]© 2026 Walmart. All rights       ║
║ reserved. | What did you think...                                                                                                                                               ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

🤖 LAYER 4: AI Agent Processing
├── ✅ OpenAI Agents SDK initialized
├── Extracted 16 transactions
├── ✅ No prompt injections detected
└── Security: Hardened system prompts | Fail-closed on suspicious input

💾 LAYER 5: Encrypted Storage
├── ✅ Saved 16 records to database
├── Database: finance_monitor.db
└── ⚠️  Running without encryption (SQLCipher not available)

📝 LAYER 6: Tamper-Evident Audit Log
├── Logged 3 audit events
├── ✅ Hash chain verified (no tampering)
└── Algorithm: SHA-256 hash chain | Append-only JSONL

                         📊 Transactions Extracted

  Date         Merchant                          Amount   Category
 ─────────────────────────────────────────────────────────────────────────
  2026-02-10   Walmart.com                        $8.99   Shopping
  2026-02-10   Walmart.com                        $6.72   Shopping
  2026-02-10   Walmart.com                       $40.09   Shopping
  2026-02-09   PayRange Inc. Amount paid $10.    $10.00   Transport
  2026-02-08   The Event Palette                 $27.20   Entertainment
  2026-02-08   The Event Palette                 $27.20   Entertainment
  2026-02-07   GoFun                             $10.98   Transport
  2026-02-03   Walmart.com                        $6.99   Shopping
  2026-02-06   Discover Card                      $4.68   Bills/Utilities
  2026-02-06   Discover Card                    $195.32   Bills/Utilities
  ...          (6 more)


         💰 Spending by Category

  Category           Amount   Percentage
 ────────────────────────────────────────
  Bills/Utilities   $395.32        61.7%
  Shopping          $167.01        26.1%
  Entertainment      $54.40         8.5%
  Transport          $20.98         3.3%
  Income              $2.92         0.5%


Total Spending: $640.63

✅ Scan completed successfully!

📄 Full debug logs saved to: logs/scan_20260212_094152.log
```

## What This Shows

- **LAYER 1** — Gmail API connection with read-only OAuth scope, fetched 100 emails
- **LAYER 2** — Blocklist pre-filter removed 21/100 promotional emails (Southwest, Groupon, Ulta, etc.) before PII redaction
- **LAYER 3** — 3-pass PII pipeline redacted 168 PII items across 10 pattern types; 23 emails failed redaction and were withheld (fail-closed)
- **PII DEMO** — Before/after snippet showing actual PII redaction (person name and address) in readable text
- **LAYER 4** — AI agent extracted 16 transactions from sanitized emails; no prompt injections detected
- **LAYER 5** — Metadata stored in database (graceful fallback to unencrypted SQLite when SQLCipher unavailable)
- **LAYER 6** — All actions logged to tamper-evident hash-chained audit trail
- **Results** — 16 transactions totaling $640.63 across 5 categories

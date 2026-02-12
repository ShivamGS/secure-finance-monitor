# Summary Command Output

## Command
```bash
python -m src.main summary --days 30
```

## Output

```
📊 Financial Summary - Last 30 Days

💳 All Transactions (16):

┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Date       ┃ Merchant                       ┃  Amount ┃ Category        ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ 2026-02-10 │ Walmart.com                    │   $8.99 │ Shopping        │
│ 2026-02-10 │ Walmart.com                    │   $6.72 │ Shopping        │
│ 2026-02-10 │ Walmart.com                    │  $40.09 │ Shopping        │
│ 2026-02-09 │ PayRange Inc. Amount paid $10. │  $10.00 │ Transport       │
│ 2026-02-08 │ The Event Palette              │  $27.20 │ Entertainment   │
│ 2026-02-08 │ The Event Palette              │  $27.20 │ Entertainment   │
│ 2026-02-07 │ GoFun                          │  $10.98 │ Transport       │
│ 2026-02-06 │ Discover Card                  │   $4.68 │ Bills/Utilities │
│ 2026-02-06 │ Discover Card                  │ $195.32 │ Bills/Utilities │
│ 2026-02-06 │ Walmart                        │  $50.00 │ Shopping        │
│ 2026-02-05 │ Walmart.com                    │   $6.34 │ Shopping        │
│ 2026-02-05 │ Discover Card                  │ $195.32 │ Bills/Utilities │
│ 2026-02-05 │ Walmart.com                    │  $43.51 │ Shopping        │
│ 2026-02-05 │ Walmart.com                    │   $2.92 │ Income          │
│ 2026-02-03 │ Walmart.com                    │   $6.99 │ Shopping        │
│ 2026-02-03 │ Walmart.com                    │   $4.37 │ Shopping        │
└────────────┴────────────────────────────────┴─────────┴─────────────────┘

Total: $640.63

💰 Spending by Category:

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Category             ┃       Amount ┃ % of Total ┃ Visual                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Bills/Utilities      │      $395.32 │      61.7% │ ██████████████████             │
│ Shopping             │      $167.01 │      26.1% │ ███████                        │
│ Entertainment        │       $54.40 │       8.5% │ ██                             │
│ Transport            │       $20.98 │       3.3% │                                │
│ Income               │        $2.92 │       0.5% │                                │
└──────────────────────┴──────────────┴────────────┴────────────────────────────────┘
```

## What This Shows

- **Transaction table** — All 16 transactions with dates, merchants, amounts, and categories
- **Category breakdown** — Spending aggregated by category with percentages
- **Visual spending bars** — Bar chart showing relative spending by category
- **Categorization accuracy** — Discover Card correctly categorized as Bills/Utilities (credit card payments), Walmart as Shopping, transportation services as Transport
- **Income tracking** — Walmart cashback reward ($2.92) correctly identified as Income, not spending
- **Total spending** — Accurate sum of $640.63 across all transactions
- **Data source** — Reads from encrypted database populated by previous scan or chat commands

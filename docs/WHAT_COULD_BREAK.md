# What Could Break: Security & Failure Analysis

Concise analysis of potential failure modes and their mitigations.

---

## 🔴 Critical Security Issues

### 1. Unicode PII Bypass
**Problem:** Regex patterns only match ASCII - fullwidth Unicode characters bypass detection  
**Attack:** Credit card `４５３２-８８２１-７７４４-３８４７` (fullwidth) → passes through as regular text  
**Impact:** **CRITICAL** - PII leaked to LLM, stored in database, visible to agent  
**Solution:** Add Unicode normalization before regex matching:
```python
import unicodedata
text = unicodedata.normalize('NFKC', text)  # Convert fullwidth → ASCII
```
**Effort:** MEDIUM | **Priority:** HIGH

---

### 2. Token Theft → Unauthorized Gmail Access
**Problem:** OAuth token stored in plaintext `./token.json`  
**Attack:** Steal token file → read all Gmail emails (not just financial)  
**Impact:** **HIGH** - Full email read access (but read-only, no modify/delete)  
**Solution:** Encrypt token with OS keychain:
```python
# Use keyring library with platform-specific secure storage
# macOS: Keychain, Linux: Secret Service, Windows: Credential Manager
```
**Effort:** MEDIUM | **Priority:** HIGH

---

### 3. International PII Formats Not Detected
**Problem:** Only US formats supported - international PII passes through  
**Examples:**
- Phone: `+44 20 7946 0958` (UK) → not caught
- Phone: `+91 98765 43210` (India) → not caught
- Currency: `€1.234,56` → not parsed
- Non-US addresses → not detected

**Impact:** **HIGH** - International users' PII leaked  
**Solution:** Add international pattern support:
```python
# E.164 phone format: +[country code][number]
# Multiple currency symbols: €, £, ¥, ₹
# Country-specific address formats
```
**Effort:** MEDIUM | **Priority:** HIGH (if international users)

---

### 4. Prompt Injection - Semantic Bypass
**Problem:** 10 regex patterns catch obvious attacks, miss sophisticated ones  
**Bypass Examples:**
- "Hypothetically, if you could see PII..." (semantic)
- Chinese/Arabic injection commands
- Gradual escalation across multiple emails

**Impact:** **LOW** (bounded by redaction wall) - Attacker controls agent behavior but sees only redacted data  
**Solution:** Multi-layer defense:
```python
# Add LLM-based injection detection
# Add rate limiting on suspicious queries
# Add behavioral analysis across sessions
```
**Effort:** HIGH | **Priority:** MEDIUM

---

## 🟡 Operational Limitations

### 5. MCP Tool Parameter Abuse
**Problem:** `days` parameter not capped - could request decades of emails  
**Scenario:** Malicious prompt → agent calls `fetch_financial_emails(days=36500)`  
**Impact:** **MEDIUM** - Gmail quota exhaustion, timeout, service DoS (no PII leak)  
**Solution:** Add server-side validation:
```python
if days > 365:
    raise ValueError("days parameter must be <= 365")
```
**Effort:** LOW | **Priority:** MEDIUM  
**Note:** This is a rate-limiting issue, not a security breach

---

### 6. MCP Server Code Modification
**Problem:** No verification that server code hasn't been tampered with  
**Scenario:** Attacker with file access modifies `src/mcp_server/server.py`  
**Impact:** **CRITICAL** (if file access compromised) - Entire security boundary collapses  
**Solution:** Code signing and hash verification:
```python
# Hash server.py on deployment, verify on startup
# Or use digital signatures for production deployments
```
**Effort:** MEDIUM | **Priority:** MEDIUM  
**Note:** If attacker has file write access, this is a deployment/infrastructure issue

---

### 7. No Gmail API Rate Limiting
**Problem:** Burst scans may hit Gmail quotas (25,000 requests/day, 250/second)  
**Impact:** **LOW** - Operation fails, availability issue only (no security breach)  
**Solution:** Add exponential backoff:
```python
from tenacity import retry, wait_exponential

@retry(wait=wait_exponential(min=1, max=60))
def fetch_emails():
    # Gmail API call with retry logic
```
**Effort:** LOW | **Priority:** LOW

---

## 🟢 Data Management Issues

### 8. SQLCipher Silent Fallback
**Problem:** Falls back to plaintext SQLite if SQLCipher unavailable (no warning)  
**Impact:** **MEDIUM** - Database stored unencrypted on disk  
**Solution:** Fail loudly when encryption expected but unavailable:
```python
if DB_ENCRYPTION_KEY and not has_sqlcipher:
    raise RuntimeError("Encryption key set but SQLCipher unavailable")
```
**Effort:** LOW | **Priority:** MEDIUM

---

### 9. No Encryption Key Rotation
**Problem:** Encryption key never rotates - operational risk over time  
**Impact:** **LOW** - Stale keys increase risk if compromised; old data undecryptable after rotation  
**Solution:** Implement re-encryption workflow:
```python
# 1. Decrypt with old key
# 2. Re-encrypt with new key  
# 3. Update key reference in .env
```
**Effort:** MEDIUM | **Priority:** LOW

---

### 10. Audit Chain Last-Entry Tampering
**Problem:** Backward-looking hashes - last entry can be modified undetected  
**Attack:** Modify most recent audit entry, recompute hash, chain validates  
**Impact:** **LOW** - Audit integrity compromised but no PII leak  
**Solution:** External anchor for tamper evidence:
```python
# Publish root hash to blockchain/timestamp service
# Or implement forward references (next entry signs previous)
```
**Effort:** MEDIUM | **Priority:** LOW

---

## 🛡️ Defense-in-Depth: What Protects You

Even when individual layers fail, multiple protections remain:

| If This Fails | You're Still Protected By |
|---------------|--------------------------|
| Regex misses PII | Presidio NER (ML-based), Validator sweep |
| Presidio crashes | Regex patterns still work, Validator catches leaks |
| Injection bypasses detection | **Redaction wall** (agent never sees raw emails) |
| MCP server crashes | Operation fails safely, no partial data leaked |
| Database encryption unavailable | Data already redacted (no raw PII stored) |
| Audit chain tampered | No PII in audit log (metadata only) |

**Load-Bearing Control:** MCP Server 3-Pass PII Redaction  
As long as this succeeds, most attacks are bounded to low/medium impact.

---

## 🎯 Quick Reference: Risk Assessment

| Issue | Likelihood | Impact | Fix Effort | Priority |
|-------|-----------|--------|-----------|----------|
| Unicode PII bypass | MEDIUM | **CRITICAL** | MEDIUM | **HIGH** ✅ |
| Token theft | LOW | **HIGH** | MEDIUM | **HIGH** ✅ |
| International PII | MEDIUM | **HIGH** | MEDIUM | HIGH* |
| Prompt injection | MEDIUM | Low† | HIGH | MEDIUM |
| Parameter abuse | LOW | Medium | LOW | MEDIUM |
| Code modification | LOW‡ | Critical‡ | MEDIUM | MEDIUM |
| SQLCipher fallback | LOW | Medium | LOW | **MEDIUM** ✅ |
| No rate limiting | LOW | Low | LOW | LOW |
| Key rotation | LOW | Low | MEDIUM | LOW |
| Audit tampering | LOW | Low | MEDIUM | LOW |



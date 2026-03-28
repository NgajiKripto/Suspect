# 🤖 Telegram Bot: Premium Data — Admin Quick Reference

> **Audience:** Authorised admins only. Keep this document internal.  
> Use `/premium_help` in the bot if you need in-chat guidance.

---

## 📋 Quick Input Format

Copy-paste the template below into the bot when prompted after clicking **[📝 Add Premium Data]**:

```
ADD_LIQ: 45.2 SOL
REM_LIQ: 0.3 SOL
FUNDING: CEX withdrawal (Binance)
TOKENS: TokenAddr1,TokenAddr2,TokenAddr3
NOTES: Repeated rugpull pattern across 3 projects
LINKS: RelatedWallet1,RelatedWallet2
```

> All fields are optional. Omit any line you do not have data for.

---

## 🔍 Field Validation Rules

| Field | Format / Regex | Example | Max Length | Notes |
|-------|---------------|---------|------------|-------|
| `ADD_LIQ` / `REM_LIQ` | `/^\d+(\.\d+)?\s*(SOL\|USDC\|USD)?$/i` | `45.2 SOL` | — | Currency suffix case-insensitive; space optional |
| `FUNDING` | Plain text, no HTML/JS | `CEX withdrawal (Binance)` | 200 chars | Escaped on render; HTML tags rejected |
| `TOKENS` / `LINKS` | Comma-separated Base58 (32–44 chars each) | `Addr1,Addr2` | 10 addresses | Validated with `@solana/web3.js`; verify on Solscan first |
| `NOTES` | Plain text, escaped on render | `Repeated pattern across 3 tokens` | 500 chars | No PII; do not reveal investigative methods |

---

## 🔄 Common Workflows

### 1 — Add premium data to a new report

```
/verify [caseNumber]
  → click [📝 Add Premium Data]
  → paste the Quick Input Format above
  → review parsed preview
  → confirm ✅
```

### 2 — Edit a single field in existing premium data

```
/edit_premium [caseNumber]
  → click ✏️ next to the field you want to change
  → enter the new value
  → review diff preview (before → after)
  → confirm ✅
```

> Rate limit: **5 edits per hour** per admin session. Plan bulk updates carefully.

### 3 — View the audit trail

```
/audit [caseNumber]
```

Returns the last **10 changes** for that case, each showing:
- Field changed
- Before / after values
- Timestamp
- Admin identifier (hashed)

---

## 🚨 Emergency Commands

| Command | Purpose | Confirmation Required |
|---------|---------|----------------------|
| `/revoke_premium [caseNumber]` | Hide premium data from the public API | ✅ Second admin approval |
| `/export_audit [YYYY-MM-DD_to_YYYY-MM-DD]` | Export audit log for compliance (CSV) | ✅ Admin token + 2FA |

---

## ⚠️ Safety Reminders

⚠️ **Never** enter PII (email address, Telegram username, real names) in `NOTES`  
⚠️ **Always** verify token addresses on [Solscan](https://solscan.io) before adding to `TOKENS` or `LINKS`  
⚠️ **Use** `/premium_help` if you are unsure about the correct input format  
⚠️ **Log out** of the admin session after sensitive operations — bot session timeout: **15 min**

---

## 🔐 Audit Log Reference

All premium field updates are written to `backend/logs/admin_audit.log` with:

```jsonc
{
  "timestamp": "…",
  "action": "PREMIUM_UPDATE",
  "walletAddress": "…",
  "caseNumber": "…",
  "changedBy": { "source": "telegram", "identifier": "<hashed>" },
  "fieldsChanged": ["addLiquidityValue"],
  "before": { "addLiquidityValue": null },
  "after":  { "addLiquidityValue": "45.2 SOL" }
}
```

Audit entries are **append-only** (file mode `0600`). Do not edit the log manually.

---

*Last Updated: {{DATE}}* <!-- Replace {{DATE}} with the actual date when updating this document, e.g. 2026-03-07 -->

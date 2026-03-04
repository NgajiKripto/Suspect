# Security Review Checklist — suspected.dev

This checklist covers all current user-facing endpoints and the Telegram bot admin interface.
Update this document whenever a new feature or endpoint is added.

---

## 1. Input Validation

| Field | Location | Rule | Status |
|-------|----------|------|--------|
| `walletAddress` | `POST /api/wallets` | Solana Base58, 32–44 chars (`/^[1-9A-HJ-NP-Za-km-z]{32,44}$/`) | ✅ validated server-side |
| `tokenAddress` | `POST /api/wallets` | Same Base58 regex, optional | ✅ validated server-side |
| `evidence.txHash` | `POST /api/wallets` | Base58, 1–100 chars, optional | ✅ validated server-side |
| `evidence.description` | `POST /api/wallets` | String, max 500 chars | ✅ validated server-side |
| `projectName` | `POST /api/wallets` | String, max 100 chars | ✅ validated server-side |
| `address` (URL param) | `GET /api/wallets/:address` | Passed to Mongoose `.findOne()` — string typing prevents injection | ✅ safe |
| `x402-payment` header | `GET /api/wallets/:address/premium` | Compared with `crypto.timingSafeEqual` to prevent timing attacks | ✅ validated |
| Telegram bot messages | `bot.on('message')` | Only processes messages from the configured `chatId` | ✅ validated |
| Telegram callback queries | `bot.on('callback_query')` | Only processes callbacks from the configured `chatId` | ✅ validated |

### Checklist for New User-Facing Fields

When adding any new input field, verify ALL of the following:

- [ ] Type-check: reject anything that isn't the expected primitive type
- [ ] Length limit: enforce an explicit maximum (and minimum where appropriate)
- [ ] Format/pattern: validate with a strict allowlist regex where applicable
- [ ] Server-side only: do NOT rely solely on client-side (HTML `maxlength`, browser regex)
- [ ] Strip or reject unexpected keys — never pass `req.body` directly to Mongoose

---

## 2. Authorization

| Endpoint | Who Can Access | Control |
|----------|----------------|---------|
| `GET /api/wallets` | Public (anyone) | No auth required — returns only `verified` wallets, forensic data excluded |
| `GET /api/wallets/:address` | Public (anyone) | No auth required — returns only `verified` wallets, forensic data excluded |
| `POST /api/wallets` | Public (anyone) | No auth — rate-limited to 5 requests / 15 min per IP |
| `GET /api/wallets/:address/premium` | Paying users | `x402-payment` header must equal `X402_PAYMENT_SECRET` (timing-safe) |
| Telegram bot commands | Admin only | Bot rejects all messages/callbacks not from `TELEGRAM_CHAT_ID` |

### Checklist for New Endpoints

- [ ] Define who should be able to call this endpoint (public / paying user / admin)
- [ ] Add auth middleware (payment header check or future JWT) before handler
- [ ] Ensure sensitive data (forensic fields, `__v`, internal IDs) is excluded from public responses via `.select()`
- [ ] Confirm the endpoint is covered by the global `rateLimit` middleware
- [ ] Apply a stricter per-route rate limit if the endpoint is write-heavy or triggers side-effects (e.g., Telegram notifications, emails)

---

## 3. Data Sensitivity Classification

| Data | Classification | Stored | Returned Publicly |
|------|---------------|--------|-------------------|
| `walletAddress` | Pseudonymous on-chain identifier | ✅ | ✅ (verified only) |
| `tokenAddress` | Pseudonymous on-chain identifier | ✅ | ✅ |
| `evidence.txHash` | Pseudonymous on-chain identifier | ✅ | ✅ |
| `evidence.description` | User-generated content | ✅ | ✅ |
| `projectName` | User-generated content | ✅ | ✅ |
| `riskScore` | Derived/computed | ✅ | ✅ |
| `forensic.*` | Sensitive analysis data (premium) | ✅ | ❌ (premium endpoint only) |
| `reporterContact` | **PII** (Telegram handle / email) | ❌ intentionally not stored | ❌ |
| `X402_PAYMENT_SECRET` | Secret credential | Env var only | ❌ |
| `TELEGRAM_BOT_TOKEN` | Secret credential | Env var only | ❌ |

### Rules

- **PII must never be persisted.** The `reporterContact` field is collected in the UI for UX purposes but is explicitly excluded from the backend handler and must never be added to the schema.
- **Secrets must live in environment variables** — never in source code or the database.
- **Premium data** (`forensic.*`) must never appear in public API responses. Always use `.select('-forensic -__v')` when building public queries.

---

## 4. Logging Requirements

| Event | Should Be Logged | Level | Notes |
|-------|-----------------|-------|-------|
| New report submitted | ✅ | INFO | Log `caseNumber`, `walletAddress`, timestamp — **not** reporter contact |
| Duplicate report (report count incremented) | ✅ | INFO | Log `caseNumber`, new `reportCount` |
| Forensic data saved via Telegram | ✅ | INFO | Log `caseNumber` only |
| Wallet verified via Telegram | ✅ | INFO | Log `caseNumber`, `riskScore` |
| Payment token mismatch on premium endpoint | ✅ | WARN | Log IP address, do **not** log the token value |
| Rate limit exceeded | ✅ | WARN | Handled automatically by `express-rate-limit` headers |
| MongoDB connection error | ✅ | ERROR | Logged + `process.exit(1)` — ✅ already implemented |
| Unhandled route error | ✅ | ERROR | Log sanitized error message, never stack trace to client |
| Bot message from unauthorized chat | ✅ | WARN | Log chat ID |

### Rules

- **Never log PII** (`reporterContact`, email, full names).
- **Never log secrets** (payment token values, bot tokens).
- Sanitize any user-generated content before including it in log output.

---

## 5. Rate Limiting

| Endpoint | Current Limit | Recommended |
|----------|--------------|-------------|
| All `GET /api/*` | 100 req / 15 min per IP | ✅ appropriate for public read |
| `POST /api/wallets` | **5 req / 15 min per IP** | ✅ strict limit added — prevents spam reports and Telegram flood |
| `GET /api/wallets/:address/premium` | 100 req / 15 min per IP | Consider tightening to 20/15min to limit data harvesting |

### Checklist for New Endpoints

- [ ] Is this endpoint callable without authentication? → apply the global limiter minimum
- [ ] Does calling this endpoint trigger a side-effect (DB write, Telegram message, email)? → add a dedicated **stricter** `rateLimit` on the specific route
- [ ] Does this endpoint return large or sensitive payloads? → add per-route limit to prevent bulk harvesting

---

## 6. Security Test Cases

### 6.1 Input Validation — `POST /api/wallets`

```bash
# ✅ PASS — valid Solana wallet address
curl -s -X POST https://suspected.dev/api/wallets \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"So11111111111111111111111111111111111111112","evidence":{"description":"test"}}'

# ❌ REJECT — too short (not valid base58, 10 chars)
curl -s -X POST https://suspected.dev/api/wallets \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"short1234"}' \
  | grep -q '"success":false' && echo "PASS: short address rejected" || echo "FAIL"

# ❌ REJECT — invalid characters (0, O, I, l not in Base58)
curl -s -X POST https://suspected.dev/api/wallets \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"0OIl000000000000000000000000000000000000000"}' \
  | grep -q '"success":false' && echo "PASS: invalid chars rejected" || echo "FAIL"

# ❌ REJECT — description exceeds 500 chars
curl -s -X POST https://suspected.dev/api/wallets \
  -H "Content-Type: application/json" \
  -d "{\"walletAddress\":\"So11111111111111111111111111111111111111112\",\"evidence\":{\"description\":\"$(python3 -c 'print("A"*501)')\"}}" \
  | grep -q '"success":false' && echo "PASS: long description rejected" || echo "FAIL"

# ❌ REJECT — invalid txHash (contains spaces / special chars)
curl -s -X POST https://suspected.dev/api/wallets \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"So11111111111111111111111111111111111111112","evidence":{"txHash":"<script>alert(1)</script>"}}' \
  | grep -q '"success":false' && echo "PASS: XSS in txHash rejected" || echo "FAIL"
```

### 6.2 Authorization — Premium Endpoint

```bash
# ❌ REJECT — no payment header → 402
curl -s -o /dev/null -w "%{http_code}" \
  https://suspected.dev/api/wallets/So11111111111111111111111111111111111111112/premium \
  | grep -q "402" && echo "PASS: 402 without payment header" || echo "FAIL"

# ❌ REJECT — wrong token → 402
curl -s -o /dev/null -w "%{http_code}" \
  -H "x402-payment: wrongtoken" \
  https://suspected.dev/api/wallets/So11111111111111111111111111111111111111112/premium \
  | grep -q "402" && echo "PASS: 402 with wrong token" || echo "FAIL"

# ❌ REJECT — forensic data must not appear on the public endpoint
curl -s https://suspected.dev/api/wallets/So11111111111111111111111111111111111111112 \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'forensic' not in d, 'FAIL: forensic data leaked'; print('PASS: forensic data not in public response')"
```

### 6.3 Rate Limiting — Submit Endpoint

```bash
# Submit 6 reports in quick succession — the 6th must be rejected with 429
for i in $(seq 1 6); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://suspected.dev/api/wallets \
    -H "Content-Type: application/json" \
    -d "{\"walletAddress\":\"So11111111111111111111111111111111111111112\"}")
  echo "Request $i: $STATUS"
done
# Expected output: requests 1–5 return 2xx or 400, request 6 returns 429
```

### 6.4 Data Sensitivity — PII Not Stored

```javascript
// Jest test: POST body with reporterContact is accepted but contact is not persisted
const response = await fetch('http://localhost:3000/api/wallets', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    walletAddress: 'So11111111111111111111111111111111111111112',
    reporterContact: 'victim@example.com'   // PII — must not be saved
  })
});
const result = await response.json();
// Verify: fetch the case and confirm reporterContact is absent
const detail = await fetch(`http://localhost:3000/api/wallets/So11111111111111111111111111111111111111112`);
const wallet = await detail.json();
console.assert(!('reporterContact' in wallet), 'FAIL: PII stored in response');
console.log('PASS: reporterContact not present in API response');
```

### 6.5 CORS — Only Allowed Origin

```bash
# ❌ REJECT — cross-origin request from untrusted origin
curl -s -H "Origin: https://evil.example.com" \
  https://suspected.dev/api/wallets \
  -I | grep -i "access-control-allow-origin" \
  | grep -q "suspected.dev" && echo "PASS: CORS restricted" || echo "WARN: check CORS header"
```

### 6.6 Security Headers — Helmet

```bash
# Verify Helmet headers are present
curl -s -I https://suspected.dev/api/wallets | grep -E \
  "X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security"
# Expected: all four headers present
```

---

## 7. Subresource Integrity (SRI)

All external stylesheets and scripts loaded from CDNs must include `integrity` and `crossorigin` attributes to prevent supply-chain attacks.

| Resource | Tag | `integrity` | Status |
|----------|-----|-------------|--------|
| Font Awesome 6.4.0 `all.min.css` | `<link>` | `sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==` | ✅ added |

### Checklist for New CDN Resources

When adding any new external `<link>` or `<script>` tag:

- [ ] Generate the SRI hash: `openssl dgst -sha512 -binary <file> | openssl base64 -A` and prefix with `sha512-`
- [ ] Add `integrity="sha512-<hash>"` to the tag
- [ ] Add `crossorigin="anonymous"` to the tag
- [ ] Add `referrerpolicy="no-referrer"` to the tag
- [ ] Record the resource and its hash in the table above

---

## 8. Environment Variable Checklist

Before deploying any new feature, ensure:

- [ ] `MONGODB_URI` — set, not hardcoded
- [ ] `TELEGRAM_BOT_TOKEN` — set, not hardcoded
- [ ] `TELEGRAM_CHAT_ID` — set, not hardcoded
- [ ] `X402_PAYMENT_SECRET` — set, not hardcoded; startup warning printed if absent
- [ ] `ALLOWED_ORIGIN` — set to production domain in production builds

---

## 9. Reporting Vulnerabilities

If you discover a security vulnerability, please contact the team privately before public disclosure.
Do not open a GitHub issue for security bugs.

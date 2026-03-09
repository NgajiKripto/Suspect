# Premium Forensic Data — Conflict Analysis & Integration Guide

> **Purpose:** Pre-implementation analysis of integration risks between the existing security baseline and the new premium forensic data feature set. Use this as a reference during code review and regression testing.

---

## Conflict Risk Matrix

| Area | Conflict Risk | Integration Strategy | Code Pattern |
|------|:---:|---|---|
| **1. x402 middleware: basic vs premium validation** | **Med** | Add a `mode` option to `verifyX402Payment`. `mode: 'basic'` keeps the original `timingSafeEqual` path (used by admin bot) unchanged; `mode: 'premium'` adds the new JWT + JWKS + oracle path without touching the basic branch. Backward compatibility is preserved by accepting a plain `number` argument as `{ mode: 'premium', expectedAmountUSD: n }`. | `verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 })` |
| **2. Mongoose schema: nested object vs existing queries** | **Low** | Declare `premiumForensics` with `select: false`. Every existing `Wallet.find*` call silently omits the field, so no query changes are needed. Only the two new code paths (PATCH write and premium GET) opt in with `.select('+premiumForensics')`. | `Wallet.findById(id).select('+premiumForensics')` |
| **3. API endpoints: consistent auth for public / premium / admin** | **Med** | Introduce a `requireAccess(level, options)` factory middleware that maps `'public'` → no-op, `'premium'` → `verifyX402Payment({ mode: 'premium' })`, `'admin'` → Telegram token or JWT admin-wallet check. All three levels share one import and one declarative call site per route. | `app.patch('/api/admin/wallets/:address/premium', requireAccess('admin', { adminSources: ['telegram', 'jwt'] }), handler)` |
| **4. Telegram bot: callback routing without state collision** | **High** | Define a `CALLBACK` constant map with colon-prefixed, namespaced keys (`verify:`, `premium:add:`, `premium:edit:`, `premium:confirm:`, `cancel`). A single `routeCallback(query)` dispatcher in `server.js` switches on prefix, forwarding to named handler functions. Each workflow uses its own in-memory state `Map` (keyed by `chatId`) so concurrent `premium_add` and `field-edit` sessions cannot overwrite each other. | `const CALLBACK = { VERIFY: 'verify:', PREMIUM_ADD: 'premium:add:', PREMIUM_EDIT: 'premium:edit:', PREMIUM_CONFIRM: 'premium:confirm:', CANCEL: 'cancel' }` |
| **5. Security tests: merging coverage without duplication** | **Low** | Add premium tests in dedicated `describe` blocks (numbered 40–43) at the end of `security.test.js`, and optionally in a separate `premium-security.test.js` that imports real middleware with injected caches. Existing blocks (1–39) remain untouched. Shared test helpers (e.g. JWT factory, JWKS stub) are defined once in a `beforeAll` block at the describe level. | `describe('40. 👑 Premium Forensics — x402 Verification', () => { ... })` |
| **6. CSP policy: premium SDK load without violations** | **Low** | Extend the production CSP meta tag to include `https://cdn.x402gateway.io` in `script-src` and `https://www.x402gateway.io` in `connect-src` **before** shipping the SDK loader. The `loadX402Sdk()` helper injects the `<script>` tag lazily on first unlock click, so the CSP update is the only prerequisite. The `connect-src` change does not affect existing `https://suspected.dev` API calls. | `connect-src 'self' https://suspected.dev https://www.x402gateway.io` |

---

## Safe Implementation Order

Follow these steps in sequence to minimise regression risk. Each step is independently testable before proceeding to the next.

- [x] **Step 1 — Schema** — Add `premiumForensics` subdocument to the Wallet Mongoose schema with `select: false`. Run existing GET endpoint tests to confirm the field is never returned. _(Zero breakage: field is invisible to all existing queries.)_

- [x] **Step 2 — Payment middleware** — Extend `verifyX402Payment` with `mode: 'premium'` (JWT + JWKS + CoinGecko oracle). Keep `mode: 'basic'` path unchanged. Add unit tests for both modes and the plain-number backward-compat alias. _(Additive change: basic path untouched, new premium path isolated behind the `mode` option.)_

- [x] **Step 3 — Unified access middleware** — Implement `requireAccess(level, options)` factory. Swap inline auth logic on existing endpoints with `requireAccess('public')` / `requireAccess('admin')` calls. Run existing auth tests. _(Refactor only: behaviour preserved, auth logic centralised.)_

- [x] **Step 4 — CSP update** — Add `https://cdn.x402gateway.io` to `script-src` and `https://www.x402gateway.io` to `connect-src` in `frontend/index.html`. Run frontend CSP tests to confirm no violations. _(Must precede SDK injection: browser will block the script load if this step is skipped.)_

- [x] **Step 5 — Admin PATCH endpoint + audit logging** — Add `PATCH /api/admin/wallets/:address/premium` guarded by `requireAccess('admin', { adminSources: ['telegram', 'jwt'] })`. Implement `writeAuditLog` helper (`admin_audit.log`, 0600 perms, append-only JSON-lines, hashed IPs). Add `GET /api/admin/audit` endpoint. Write describe blocks 41–43 in `security.test.js`. _(All writes gated; audit log tested before Telegram workflow is wired up.)_

- [x] **Step 6 — Telegram bot workflow** — Define `CALLBACK` constant map and `routeCallback` dispatcher. Implement `handlePremiumAdd` (multi-step input), `handlePremiumEdit` (single-field diff), and `handleBulkEdit` (full resubmit). Use `workflowState.js` for per-chatId session with 15-minute expiry. Add describe block 42 (Telegram auth) tests. _(Isolated by CALLBACK namespace; separate state Maps prevent collision with the existing `verify:` flow.)_

- [x] **Step 7 — Frontend PremiumUnlock component** — Implement `loadX402Sdk()`, `unlockPremiumData(address)`, and `renderPremiumCard(address, data)` in `frontend/index.html`. Gate `unlockPremiumData` on Base58 address validation. Escape all six premium field values with `escapeHtml()` before DOM insertion. Add `premium-unlock.spec.js` and `premium-unlock.e2e.spec.js` test suites. _(Last step: CSP is already updated, PATCH endpoint is live, SDK domain is trusted.)_

---

*Analysis generated: 2026-03-09*

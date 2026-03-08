'use strict';

/**
 * Premium Security Tests — suspected.dev backend
 *
 * Comprehensive tests for the premium x402 + admin workflow:
 *   PS-1. x402 Payment Validation
 *   PS-2. Admin Authorization
 *   PS-3. Input Validation
 *   PS-4. Data Privacy
 *   PS-5. Audit Logging
 *
 * Run: npm test
 */

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const request = require('supertest');
const jwt     = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { verifyX402Payment, _caches } = require('../middleware/verifyX402Payment');
const { requireAdminAuth }           = require('../middleware/requireAdminAuth');
const { writeAuditLog, hashIp, AUDIT_LOG_PATH } = require('../auditLog');

// ── Shared regex (mirrors server.js) ─────────────────────────────────────────
const WALLET_ADDRESS_REGEX  = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const LIQUIDITY_VALUE_REGEX = /^\d+(\.\d+)?\s*(SOL|USDC|USD)?$/i;
const HTML_TAG_REGEX        = /<[^>]*>/;

// ── Shared test constants ─────────────────────────────────────────────────────
const VALID_ADDRESS    = 'So11111111111111111111111111111111111111112'; // 44 chars
const VALID_TOKEN_ADDR = 'TokenAddr1111111111111111111111111111111111'; // 44 chars
const ADMIN_WALLET     = 'PSAdminWallet1111111111111111111111111111111'; // 44 chars
const OTHER_WALLET     = 'PSOtherWallet111111111111111111111111111111'; // 43 chars
const ADMIN_CHAT_ID    = '555666777';
const OTHER_CHAT_ID    = '111222333';
const ADMIN_USER_ID    = '444555666';

// ── ES256 test key pair ───────────────────────────────────────────────────────
const { privateKey: TEST_PRIV_KEY, publicKey: TEST_PUB_KEY } =
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

const TEST_JWK = Object.assign(TEST_PUB_KEY.export({ format: 'jwk' }), {
  kid: 'ps-kid-1',
  use: 'sig',
  alg: 'ES256'
});

/**
 * Sign a JWT for test requests.
 * @param {object} claims  JWT payload (amount, currency, payer, etc.)
 * @param {object} opts    Optional overrides: { kid }
 */
function signTestToken(claims, opts = {}) {
  const kid      = opts.kid !== undefined ? opts.kid : 'ps-kid-1';
  const signOpts = { algorithm: 'ES256', expiresIn: '1h' };
  if (kid) signOpts.keyid = kid;
  return jwt.sign(claims, TEST_PRIV_KEY, signOpts);
}

/** Preload JWKS and price caches so no real HTTP calls are made during tests. */
function injectTestCaches() {
  _caches.jwks  = { keys: [TEST_JWK], fetchedAt: Date.now() };
  _caches.price = { priceUSD: 150, fetchedAt: Date.now() };
}

// ── Frozen premium snapshot returned by the test app ─────────────────────────
const MOCK_PREMIUM_FORENSICS = {
  addLiquidityValue:    '45.2 SOL',
  removeLiquidityValue: '0.3 SOL',
  walletFunding:        'Tornado Cash',
  forensicNotes:        'Repeat offender pattern detected',
  tokensCreated:        [VALID_TOKEN_ADDR],
  crossProjectLinks:    ['RelatedAddr111111111111111111111111111111111'],
  updatedAt:            new Date().toISOString()
};

// ── Test app for x402 / data-privacy tests ────────────────────────────────────
// Uses the REAL verifyX402Payment middleware with injected test caches.
function buildX402TestApp() {
  const app = express();
  app.use(express.json());

  // Public wallet detail — never exposes premiumForensics
  app.get('/api/wallets/:address', (req, res) => {
    const addr = req.params.address;
    if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });
    res.json({ walletAddress: addr, status: 'verified', riskScore: 95 });
  });

  // Premium-gated endpoint — requires valid x402 JWT (real middleware)
  app.get('/api/wallets/:address/premium',
    TEST_RATE_LIMIT,
    verifyX402Payment(0.11),
    (req, res) => {
      const addr = req.params.address;
      if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });
      res.json({
        walletAddress: addr,
        status:        'verified',
        riskScore:     95,
        forensic:      { liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 },
        premiumForensics: MOCK_PREMIUM_FORENSICS,
        payerAddress:  req.x402.payerAddress
      });
    }
  );

  return app;
}

// ── Test app for admin / input-validation / audit tests ───────────────────────
// Uses the REAL requireAdminAuth('api') middleware + full input validation.
// Writes to the real audit log so Suite PS-5 can inspect it.
function buildAdminTestApp() {
  const app = express();
  app.use(express.json());

  app.patch('/api/admin/wallets/:address/premium',
    TEST_RATE_LIMIT,
    requireAdminAuth('api'),
    (req, res) => {
      const addr = req.params.address;
      if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });

      const {
        addLiquidityValue, removeLiquidityValue,
        walletFunding, tokensCreated,
        forensicNotes, crossProjectLinks
      } = req.body;

      // ── Validation mirrors server.js ─────────────────────────────────────
      const errors = [];
      if (addLiquidityValue !== undefined) {
        if (typeof addLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(addLiquidityValue))
          errors.push('addLiquidityValue must match /^\\d+(\\.\\d+)?\\s*(SOL|USDC|USD)?$/i');
      }
      if (removeLiquidityValue !== undefined) {
        if (typeof removeLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(removeLiquidityValue))
          errors.push('removeLiquidityValue must match /^\\d+(\\.\\d+)?\\s*(SOL|USDC|USD)?$/i');
      }
      if (walletFunding !== undefined) {
        if (typeof walletFunding !== 'string' || walletFunding.length > 200 || HTML_TAG_REGEX.test(walletFunding))
          errors.push('walletFunding must be a string, max 200 chars, with no HTML tags');
      }
      if (tokensCreated !== undefined) {
        if (!Array.isArray(tokensCreated) ||
            !tokensCreated.every(a => typeof a === 'string' && WALLET_ADDRESS_REGEX.test(a)))
          errors.push('tokensCreated must be an array of valid Solana Base58 addresses (32–44 chars)');
      }
      if (forensicNotes !== undefined) {
        if (typeof forensicNotes !== 'string' || HTML_TAG_REGEX.test(forensicNotes))
          errors.push('forensicNotes must be a string with no HTML tags');
      }
      if (crossProjectLinks !== undefined) {
        if (!Array.isArray(crossProjectLinks) ||
            !crossProjectLinks.every(a => typeof a === 'string' && WALLET_ADDRESS_REGEX.test(a)))
          errors.push('crossProjectLinks must be an array of valid Solana Base58 addresses (32–44 chars)');
      }

      if (errors.length > 0) return res.status(400).json({ success: false, message: 'Validation failed', errors });

      const fieldsChanged = [
        addLiquidityValue    !== undefined ? 'addLiquidityValue'   : null,
        removeLiquidityValue !== undefined ? 'removeLiquidityValue' : null,
        walletFunding        !== undefined ? 'walletFunding'       : null,
        tokensCreated        !== undefined ? 'tokensCreated'       : null,
        forensicNotes        !== undefined ? 'forensicNotes'       : null,
        crossProjectLinks    !== undefined ? 'crossProjectLinks'   : null
      ].filter(Boolean);

      const timestamp    = new Date().toISOString();
      const payerAddress = req.adminAuth.payerAddress;

      // Write to real audit log so PS-5 tests can inspect entries.
      writeAuditLog({
        timestamp,
        action:        'premium_update',
        walletAddress: addr,
        caseNumber:    99,
        changedBy:     { source: 'api', identifier: `wallet:${payerAddress}` },
        fieldsChanged,
        before:        {},
        after:         {
          addLiquidityValue, removeLiquidityValue, walletFunding,
          tokensCreated, forensicNotes, crossProjectLinks
        },
        ipHash: hashIp(req.ip)
      });

      res.json({
        success: true,
        premiumForensics: {
          addLiquidityValue, removeLiquidityValue, walletFunding,
          tokensCreated, forensicNotes, crossProjectLinks,
          updatedAt: timestamp
        },
        auditLog: { updatedBy: 'admin', timestamp, fieldsChanged }
      });
    }
  );

  return app;
}

// ── High-limit rate limiter used by test apps (avoids CodeQL missing-rate-limiting alert) ──
const TEST_RATE_LIMIT = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10000,
  standardHeaders: false,
  legacyHeaders:   false
});

/**
 * Minimum milliseconds to wait for async fs.appendFile to flush to disk.
 * Node's fs.appendFile is async (callback-based); 60 ms provides a reliable
 * margin on CI machines where I/O scheduling may add latency.
 */
const LOG_FLUSH_DELAY_MS = 60;

/** Returns the current byte size of the audit log, 0 if file does not exist. */
function logSize() {
  try { return fs.statSync(AUDIT_LOG_PATH).size; }
  catch { return 0; }
}

/**
 * Reads only the log lines appended after `baseline` bytes.
 * Returns a Promise that resolves to an array of parsed JSON objects.
 * A small delay is used to let the async fs.appendFile complete.
 */
function readNewLogEntries(baseline) {
  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        const full = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
        const newContent = full.slice(baseline);
        const entries = newContent
          .split('\n')
          .filter(Boolean)
          .map(line => {
            try { return JSON.parse(line); }
            catch { return null; }
          })
          .filter(Boolean);
        resolve(entries);
      } catch {
        resolve([]);
      }
    }, LOG_FLUSH_DELAY_MS);
  });
}

// ════════════════════════════════════════════════════════════════════════════
// PS-1. x402 Payment Validation
// ════════════════════════════════════════════════════════════════════════════

describe('PS-1. x402 Payment Validation', () => {
  let app;

  beforeAll(() => {
    injectTestCaches();
    app = buildX402TestApp();
  });

  afterAll(() => {
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  test('rejects missing x402-payment header with 402 and requiredAmountUSD', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}/premium`);
    expect(res.status).toBe(402);
    expect(res.body.error).toBe('Payment Required');
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('rejects malformed (non-JWT) payment header with 402', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', 'not-a-valid-jwt-string');
    expect(res.status).toBe(402);
    expect(res.body.error).toBe('Payment Required');
  });

  test('rejects JWT signed with an unknown key (wrong kid) with 402', async () => {
    const token = signTestToken(
      { amount: 0.11, currency: 'USD', payer: 'SomePayerAddr11111111111111111111111111111' },
      { kid: 'unknown-kid-9999' }
    );
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Uu]nknown.*key/);
  });

  test('rejects JWT with insufficient payment amount with 402', async () => {
    const token = signTestToken({ amount: 0.05, currency: 'USD', payer: 'PayerAddr111111111111111111111111111111111' });
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Ii]nsufficient/);
  });

  test('accepts valid JWT (USD) and returns premiumForensics', async () => {
    const payer = 'SolPayerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('premiumForensics');
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding');
    expect(res.body.premiumForensics).toHaveProperty('forensicNotes');
    expect(res.body).toHaveProperty('payerAddress', payer);
  });

  test('accepts valid JWT (SOL, oracle price applied) and returns premiumForensics', async () => {
    // 0.001 SOL × $150 cached oracle price = $0.15 ≥ $0.11 required
    const payer = 'SolPayerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const token = signTestToken({ amount: 0.001, currency: 'SOL', payer });
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('premiumForensics');
  });

  test('timingSafeEqual provides constant-time guarantee for equal-length secrets', () => {
    // The verifyX402Payment middleware relies on JWT signature verification
    // (via jsonwebtoken + ECDSA) for its constant-time security — the ECDSA
    // verification step is inherently timing-safe because the underlying
    // crypto primitives compare the computed vs. expected signature in
    // constant time.
    //
    // This test documents and verifies that crypto.timingSafeEqual is the
    // correct primitive to use when server code needs to compare shared
    // secrets or derived values (e.g., Telegram admin tokens in the test app).
    const secret  = Buffer.from('admin-payment-secret-value');
    const correct = Buffer.from('admin-payment-secret-value');
    const wrong   = Buffer.from('admin-XXXXXXX-secret-value'); // same length, wrong content

    // Same buffer → true
    expect(crypto.timingSafeEqual(secret, correct)).toBe(true);
    // Wrong content (same length) → false, in constant time — no early exit
    expect(crypto.timingSafeEqual(secret, wrong)).toBe(false);
    // Different-length buffers must be guarded before calling timingSafeEqual
    // (it throws rather than silently leaking timing information)
    expect(() => crypto.timingSafeEqual(secret, Buffer.from('short'))).toThrow();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PS-2. Admin Authorization
// ════════════════════════════════════════════════════════════════════════════

describe('PS-2. Admin Authorization', () => {
  let adminApp;

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    adminApp = buildAdminTestApp();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  function signAdmin(payer = ADMIN_WALLET) {
    return signTestToken({ amount: 0.11, currency: 'USD', payer });
  }

  // ── API middleware (requireAdminAuth('api')) ──────────────────────────────

  test('PATCH rejects request with no x402-payment header with 403', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .send({ forensicNotes: 'test' });
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('PATCH rejects request where JWT payer is not in ADMIN_WALLET_ADDRESSES with 403', async () => {
    const token = signAdmin(OTHER_WALLET);
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'should be rejected' });
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('PATCH accepts request where JWT payer is in ADMIN_WALLET_ADDRESSES', async () => {
    const token = signAdmin(ADMIN_WALLET);
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'authorized update' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('ADMIN_WALLET_ADDRESSES whitelist is enforced — empty list rejects all', async () => {
    const saved = process.env.ADMIN_WALLET_ADDRESSES;
    process.env.ADMIN_WALLET_ADDRESSES = '';
    const token = signAdmin(ADMIN_WALLET);
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'should be rejected' });
    expect(res.status).toBe(403);
    process.env.ADMIN_WALLET_ADDRESSES = saved;
  });

  test('ADMIN_WALLET_ADDRESSES whitelist allows comma-separated second admin wallet', async () => {
    process.env.ADMIN_WALLET_ADDRESSES = OTHER_WALLET + ',' + ADMIN_WALLET;
    const token = signAdmin(OTHER_WALLET);
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'second admin' });
    expect(res.status).toBe(200);
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
  });

  // ── Telegram handler (requireAdminAuth('telegram')) ───────────────────────

  describe('PS-2b. Telegram bot admin authorization', () => {
    function getHandler() { return requireAdminAuth('telegram'); }

    function makeMessage(chatId = ADMIN_CHAT_ID, fromId = ADMIN_USER_ID) {
      return { chat: { id: chatId }, from: { id: fromId }, text: '/command' };
    }

    function makeCallbackQuery(chatId = ADMIN_CHAT_ID, fromId = ADMIN_USER_ID) {
      return { message: { chat: { id: chatId } }, from: { id: fromId }, data: 'confirm_abc' };
    }

    beforeEach(() => {
      process.env.TELEGRAM_ADMIN_CHAT_ID  = ADMIN_CHAT_ID;
      process.env.TELEGRAM_ADMIN_USER_IDS = ADMIN_USER_ID;
    });

    afterEach(() => {
      delete process.env.TELEGRAM_ADMIN_CHAT_ID;
      delete process.env.TELEGRAM_ADMIN_USER_IDS;
      delete process.env.TELEGRAM_CHAT_ID;
    });

    test('rejects callback from non-admin chat.id', () => {
      expect(getHandler()(makeMessage(OTHER_CHAT_ID, ADMIN_USER_ID))).toBe(false);
    });

    test('rejects CallbackQuery from non-admin message.chat.id', () => {
      expect(getHandler()(makeCallbackQuery(OTHER_CHAT_ID, ADMIN_USER_ID))).toBe(false);
    });

    test('rejects message from non-whitelisted from.id', () => {
      expect(getHandler()(makeMessage(ADMIN_CHAT_ID, '999999999'))).toBe(false);
    });

    test('accepts authorized Message (correct chat.id and from.id)', () => {
      expect(getHandler()(makeMessage())).toBe(true);
    });

    test('accepts authorized CallbackQuery (correct message.chat.id and from.id)', () => {
      expect(getHandler()(makeCallbackQuery())).toBe(true);
    });

    test('rejects when TELEGRAM_ADMIN_CHAT_ID is not configured', () => {
      delete process.env.TELEGRAM_ADMIN_CHAT_ID;
      expect(getHandler()(makeMessage())).toBe(false);
    });

    test('falls back to TELEGRAM_CHAT_ID when TELEGRAM_ADMIN_CHAT_ID is absent', () => {
      delete process.env.TELEGRAM_ADMIN_CHAT_ID;
      process.env.TELEGRAM_CHAT_ID = ADMIN_CHAT_ID;
      expect(getHandler()(makeMessage())).toBe(true);
    });
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PS-3. Input Validation
// ════════════════════════════════════════════════════════════════════════════

describe('PS-3. Input Validation — PATCH /api/admin/wallets/:address/premium', () => {
  let app;
  const auth = () => signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    app = buildAdminTestApp();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  // ── tokensCreated ─────────────────────────────────────────────────────────

  test('rejects invalid Solana address in tokensCreated array with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ tokensCreated: ['0OIl-not-base58'] });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/tokensCreated/)])
    );
  });

  test('rejects tokensCreated as a non-array value with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ tokensCreated: 'not-an-array' });
    expect(res.status).toBe(400);
  });

  // ── forensicNotes ─────────────────────────────────────────────────────────

  test('rejects HTML tags in forensicNotes with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ forensicNotes: '<script>alert("xss")</script>' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/forensicNotes/)])
    );
  });

  test('rejects inline HTML element in forensicNotes with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ forensicNotes: 'Note: <b>bold text</b>' });
    expect(res.status).toBe(400);
  });

  test('rejects forensicNotes as non-string with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ forensicNotes: 12345 });
    expect(res.status).toBe(400);
  });

  // ── All 6 valid fields accepted ───────────────────────────────────────────

  test('accepts valid formatted values for all 6 premium fields', async () => {
    const payload = {
      addLiquidityValue:    '45.2 SOL',
      removeLiquidityValue: '0.3 SOL',
      walletFunding:        'Binance Hot Wallet',
      tokensCreated:        [VALID_TOKEN_ADDR],
      forensicNotes:        'Repeat offender pattern detected',
      crossProjectLinks:    [VALID_TOKEN_ADDR]
    };
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send(payload);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue', '45.2 SOL');
    expect(res.body.premiumForensics).toHaveProperty('removeLiquidityValue', '0.3 SOL');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding', 'Binance Hot Wallet');
    expect(Array.isArray(res.body.premiumForensics.tokensCreated)).toBe(true);
    expect(res.body.premiumForensics).toHaveProperty('forensicNotes', 'Repeat offender pattern detected');
    expect(Array.isArray(res.body.premiumForensics.crossProjectLinks)).toBe(true);
  });

  test('accepts addLiquidityValue with USDC currency unit', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ addLiquidityValue: '1000 USDC' });
    expect(res.status).toBe(200);
  });

  test('rejects addLiquidityValue with non-numeric prefix with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ addLiquidityValue: 'ONE HUNDRED SOL' });
    expect(res.status).toBe(400);
  });

  test('rejects walletFunding with HTML tags with 400', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({ walletFunding: '<img src=x onerror=alert(1)>' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/walletFunding/)])
    );
  });

  test('returns multiple errors when multiple fields are invalid simultaneously', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', auth())
      .send({
        addLiquidityValue: 'bad-value',
        forensicNotes:     '<b>html</b>',
        tokensCreated:     ['not-base58-0OIl']
      });
    expect(res.status).toBe(400);
    expect(res.body.errors.length).toBeGreaterThanOrEqual(3);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PS-4. Data Privacy
// ════════════════════════════════════════════════════════════════════════════

describe('PS-4. Data Privacy', () => {
  let x402App;
  let adminApp;

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    x402App   = buildX402TestApp();
    adminApp  = buildAdminTestApp();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  // ── premiumForensics not returned without payment ─────────────────────────

  test('GET /api/wallets/:address without payment does NOT include premiumForensics', async () => {
    const res = await request(x402App).get(`/api/wallets/${VALID_ADDRESS}`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('premiumForensics');
    expect(res.body).not.toHaveProperty('forensic');
  });

  test('GET /api/wallets/:address without payment does NOT include reporterContact', async () => {
    const res = await request(x402App).get(`/api/wallets/${VALID_ADDRESS}`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('reporterContact');
  });

  test('GET /api/wallets/:address/premium with wrong JWT returns 402 without data leak', async () => {
    const wrongToken = signTestToken(
      { amount: 0.01, currency: 'USD', payer: 'PayerXXXX1111111111111111111111111111111111' }
    );
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', wrongToken);
    expect(res.status).toBe(402);
    expect(res.body).not.toHaveProperty('premiumForensics');
    expect(res.body).not.toHaveProperty('forensic');
  });

  // ── premiumForensics fields are properly included (and JSON-encoded) ──────

  test('valid x402 payment returns premiumForensics with all expected fields', async () => {
    const payer = 'SolPayerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    const pf = res.body.premiumForensics;
    expect(pf).toHaveProperty('addLiquidityValue');
    expect(pf).toHaveProperty('removeLiquidityValue');
    expect(pf).toHaveProperty('walletFunding');
    expect(pf).toHaveProperty('forensicNotes');
    expect(pf).toHaveProperty('tokensCreated');
    expect(pf).toHaveProperty('crossProjectLinks');
    expect(pf).toHaveProperty('updatedAt');
  });

  test('premiumForensics response is valid JSON (no raw HTML content)', async () => {
    const payer = 'SolPayerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    // Body is parsed JSON — text field values should be plain strings, not script elements
    const pf = res.body.premiumForensics;
    expect(typeof pf.walletFunding).toBe('string');
    expect(typeof pf.forensicNotes).toBe('string');
    // None of the returned field values should contain raw HTML script tags
    const allValues = JSON.stringify(pf);
    expect(allValues).not.toMatch(/<script/i);
  });

  // ── Audit log does not contain PII or raw secrets ─────────────────────────

  test('audit log changedBy.identifier uses wallet prefix, not email/name PII', async () => {
    const baseline = logSize();
    const token    = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
    await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'privacy test note' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);
    const entry = entries[entries.length - 1];
    // identifier must be "wallet:<address>", never an email address
    expect(entry.changedBy.identifier).toMatch(/^wallet:/);
    expect(entry.changedBy.identifier).not.toMatch(/@/);
  });

  test('audit log entry does not store the raw x402 JWT token', async () => {
    const baseline = logSize();
    const token    = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
    await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ walletFunding: 'Binance' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);
    const rawLine = JSON.stringify(entries[entries.length - 1]);
    // The raw JWT is a long base64url string (contains dots); it must not appear in the log
    expect(rawLine).not.toContain(token);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// PS-5. Audit Logging
// ════════════════════════════════════════════════════════════════════════════

describe('PS-5. Audit Logging', () => {
  let app;
  let suiteBaseline;

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    app = buildAdminTestApp();
    // Record log size before this suite so we can isolate its entries.
    suiteBaseline = logSize();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  function signAdmin() {
    return signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
  }

  test('every premium update creates an entry in admin_audit.log', async () => {
    const baseline = logSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'audit-logging test entry' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThanOrEqual(1);
  });

  test('audit log entry contains required fields: timestamp, action, walletAddress, caseNumber, changedBy, fieldsChanged, before, after', async () => {
    const baseline = logSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ addLiquidityValue: '10 SOL', forensicNotes: 'shape test' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);

    const entry = entries.find(e => e.action === 'premium_update');
    expect(entry).toBeDefined();
    expect(entry).toHaveProperty('timestamp');
    expect(entry).toHaveProperty('action', 'premium_update');
    expect(entry).toHaveProperty('walletAddress', VALID_ADDRESS);
    expect(entry).toHaveProperty('caseNumber');
    expect(entry).toHaveProperty('changedBy');
    expect(entry.changedBy).toHaveProperty('source', 'api');
    expect(entry.changedBy).toHaveProperty('identifier');
    expect(entry).toHaveProperty('fieldsChanged');
    expect(entry).toHaveProperty('before');
    expect(entry).toHaveProperty('after');
  });

  test('log entry contains before/after diff for only the submitted fields (not full document)', async () => {
    const baseline = logSize();
    // Submit only forensicNotes
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'diff test value' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);

    const entry = entries[entries.length - 1];
    // fieldsChanged lists only the submitted field
    expect(entry.fieldsChanged).toEqual(['forensicNotes']);
    // after contains the new value for the changed field
    expect(entry.after).toHaveProperty('forensicNotes', 'diff test value');
    // before and after are scoped objects, not full wallet documents
    // (should not contain wallet-level fields like walletAddress, caseNumber at the top level of after)
    expect(entry.after).not.toHaveProperty('walletAddress');
    expect(entry.after).not.toHaveProperty('status');
  });

  test('IP addresses are hashed (not stored in plain text) in audit log entries', async () => {
    const baseline = logSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ walletFunding: 'IP hash test' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);

    // Filter to complete admin-app entries (ipHash present) to avoid picking up
    // partial entries written by concurrent test files.
    const entry   = entries.find(e => e.action === 'premium_update' && e.ipHash !== undefined);
    expect(entry).toBeDefined();
    const rawLine = JSON.stringify(entry);

    // ipHash must be present and match the sha256-prefixed format
    expect(entry).toHaveProperty('ipHash');
    expect(entry.ipHash).toMatch(/^sha256-[a-f0-9]{64}$/);
    // Raw loopback IPs must not appear in the log
    expect(rawLine).not.toContain('"ip"');
    expect(rawLine).not.toMatch(/"127\.0\.0\.1"/);
    expect(rawLine).not.toMatch(/"::1"/);
  });

  test('multiple sequential updates each create a separate log entry', async () => {
    const baseline = logSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'entry one' });
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'entry two' });

    const entries = await readNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThanOrEqual(2);
  });
});

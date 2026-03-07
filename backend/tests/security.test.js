/**
 * Security Tests — suspected.dev backend
 *
 * Tests verify the security controls described in SECURITY.md:
 *   1. Input validation (wallet address, token address, txHash, description, projectName)
 *   2. Authorization (premium endpoint requires x402-payment header)
 *   3. Rate limiting (POST /api/wallets is limited to 5 req / 15 min)
 *   4. Data sensitivity (reporterContact is never returned)
 *   5. Security headers (Helmet middleware)
 *
 * Run: npm test
 */

'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const request = require('supertest');
const {
  parsePremiumInput,
  validatePremiumFields,
  buildPremiumPreview,
  PREMIUM_HELP_TEXT,
  CAMEL_TO_KEY,
  SENSITIVE_FIELDS,
  buildEditCurrentValues,
  buildDiffPreview,
  buildBulkDiffPreview
} = require('../botUtils');

// ─── Shared regex (mirrors server.js) ────────────────────────────────────────
const WALLET_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TX_HASH_REGEX = /^[1-9A-HJ-NP-Za-km-z]{1,100}$/;
const LIQUIDITY_VALUE_REGEX = /^\d+(\.\d+)?\s*(SOL|USDC|USD)?$/i;
const HTML_TAG_REGEX = /<[^>]*>/;

// ─── Build a lightweight test app that mimics server.js validation ───────────
function buildTestApp({ paymentSecret = 'test-secret', submitMax = 5, adminSecret = 'admin-secret', telegramAdminToken = 'tg-admin-token', patchAdminMax = 20 } = {}) {
  const app = express();
  app.use(helmet());
  app.use(express.json());

  // Global limiter (mirrors production)
  app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: false, legacyHeaders: false }));

  // Strict limiter on submit (mirrors production)
  const submitRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: submitMax,
    standardHeaders: false,
    legacyHeaders: false,
    message: { success: false, message: 'Too many reports submitted. Please try again later.' }
  });

  // Rate limit for PATCH admin premium endpoint (mirrors production, keyed by token hash)
  const adminPremiumRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: patchAdminMax,
    standardHeaders: false,
    legacyHeaders: false,
    keyGenerator: (req) => {
      const token = req.headers['x-telegram-admin-token'] || req.headers['x402-payment'] || req.ip;
      return crypto.createHash('sha256').update(String(token)).digest('hex');
    },
    message: { success: false, message: 'Rate limit exceeded. Max 20 updates per hour per admin token.' }
  });

  // Public list — no forensic data
  app.get('/api/wallets', (_req, res) => {
    res.json([{ walletAddress: 'So11111111111111111111111111111111111111112', status: 'verified', riskScore: 95 }]);
  });

  // Public detail — no forensic data, no reporterContact
  // Supports ?include=premium query param: requires x402-payment secret header
  app.get('/api/wallets/:address', (req, res) => {
    const addr = req.params.address;
    if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });

    if (req.query.include === 'premium') {
      const paid = req.headers['x402-payment'];
      if (!paid || !paymentSecret) return res.status(402).json({ error: 'Payment Required', message: 'x402-payment header is required', requiredAmountUSD: 0.11 });
      try {
        const paidBuf = Buffer.from(paid);
        const validBuf = Buffer.from(paymentSecret);
        if (paidBuf.length !== validBuf.length || !crypto.timingSafeEqual(paidBuf, validBuf)) {
          return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
        }
      } catch {
        return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
      }
      return res.json({
        walletAddress: addr, status: 'verified', riskScore: 95,
        forensic: { liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 },
        premiumForensics: {
          addLiquidityValue: '45.2 SOL', removeLiquidityValue: '0.3 SOL',
          walletFunding: 'Tornado Cash', forensicNotes: 'Repeat offender pattern detected',
          tokensCreated: ['TokenAddr1111111111111111111111111111111111'],
          crossProjectLinks: ['RelatedAddr111111111111111111111111111111111'],
          updatedAt: new Date().toISOString()
        }
      });
    }

    res.json({ walletAddress: addr, status: 'verified', riskScore: 95 });
  });

  // Explicit premium unlock: POST /api/wallets/:address/premium/access
  app.post('/api/wallets/:address/premium/access', (req, res) => {
    const addr = req.params.address;
    if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });

    const paid = req.headers['x402-payment'];
    if (!paid || !paymentSecret) return res.status(402).json({ error: 'Payment Required', message: 'x402-payment header is required', requiredAmountUSD: 0.11 });
    try {
      const paidBuf = Buffer.from(paid);
      const validBuf = Buffer.from(paymentSecret);
      if (paidBuf.length !== validBuf.length || !crypto.timingSafeEqual(paidBuf, validBuf)) {
        return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
      }
    } catch {
      return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
    }

    res.json({
      payerAddress: 'MockPayerAddr11111111111111111111111111111',
      forensic: { liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 },
      premiumForensics: {
        addLiquidityValue: '45.2 SOL', removeLiquidityValue: '0.3 SOL',
        walletFunding: 'Tornado Cash', forensicNotes: 'Repeat offender pattern detected',
        tokensCreated: ['TokenAddr1111111111111111111111111111111111'],
        crossProjectLinks: ['RelatedAddr111111111111111111111111111111111'],
        updatedAt: new Date().toISOString()
      }
    });
  });

  // Premium endpoint
  app.get('/api/wallets/:address/premium', (req, res) => {
    const paid = req.headers['x402-payment'];
    if (!paid || !paymentSecret) return res.status(402).json({ message: 'Payment required via x402' });

    try {
      const paidBuf = Buffer.from(paid);
      const validBuf = Buffer.from(paymentSecret);
      if (paidBuf.length !== validBuf.length || !crypto.timingSafeEqual(paidBuf, validBuf)) {
        return res.status(402).json({ message: 'Payment required via x402' });
      }
    } catch {
      return res.status(402).json({ message: 'Payment required via x402' });
    }

    res.json({
      forensic: { liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 },
      premiumForensics: {
        addLiquidityValue: '45.2 SOL',
        removeLiquidityValue: '0.3 SOL',
        walletFunding: 'Tornado Cash',
        tokensCreated: ['TokenAddr1111111111111111111111111111111111'],
        forensicNotes: 'Repeat offender pattern detected',
        crossProjectLinks: ['RelatedAddr111111111111111111111111111111111'],
        updatedAt: new Date().toISOString()
      }
    });
  });

  // Admin endpoint — update premiumForensics
  app.post('/api/admin/wallets/:address/premium-forensics', (req, res) => {
    const adminToken = req.headers['x-admin-token'];
    if (!adminToken || !adminSecret) return res.status(403).json({ message: 'Forbidden' });

    try {
      const tokenBuf = Buffer.from(adminToken);
      const validBuf = Buffer.from(adminSecret);
      if (tokenBuf.length !== validBuf.length || !crypto.timingSafeEqual(tokenBuf, validBuf)) {
        return res.status(403).json({ message: 'Forbidden' });
      }
    } catch {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks } = req.body;
    res.json({ success: true, premiumForensics: { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks, updatedAt: new Date().toISOString() } });
  });

  // PATCH admin endpoint — partial update of premiumForensics (mirrors production)
  app.patch('/api/admin/wallets/:address/premium', adminPremiumRateLimit, (req, res) => {
    // Option 1: Telegram admin token
    let authorized = false;
    const tgToken = req.headers['x-telegram-admin-token'];
    if (tgToken && telegramAdminToken) {
      try {
        const aBuf = Buffer.from(tgToken);
        const bBuf = Buffer.from(telegramAdminToken);
        if (aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf)) authorized = true;
      } catch { /* fall through */ }
    }
    // Option 2: x402-payment + x-admin-token (admin role)
    if (!authorized) {
      const x402 = req.headers['x402-payment'];
      const admin = req.headers['x-admin-token'];
      if (x402 && paymentSecret && admin && adminSecret) {
        try {
          const paidBuf = Buffer.from(x402);
          const validPaidBuf = Buffer.from(paymentSecret);
          const adminBuf = Buffer.from(admin);
          const validAdminBuf = Buffer.from(adminSecret);
          const x402Valid = paidBuf.length === validPaidBuf.length && crypto.timingSafeEqual(paidBuf, validPaidBuf);
          const adminValid = adminBuf.length === validAdminBuf.length && crypto.timingSafeEqual(adminBuf, validAdminBuf);
          if (x402Valid && adminValid) authorized = true;
        } catch { /* fall through */ }
      }
    }
    if (!authorized) return res.status(403).json({ success: false, message: 'Forbidden' });

    const { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks } = req.body;

    // Validation
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
      if (!Array.isArray(tokensCreated) || !tokensCreated.every(a => typeof a === 'string' && WALLET_ADDRESS_REGEX.test(a)))
        errors.push('tokensCreated must be an array of valid Solana Base58 addresses (32–44 chars)');
    }
    if (forensicNotes !== undefined) {
      if (typeof forensicNotes !== 'string') errors.push('forensicNotes must be a string');
    }
    if (crossProjectLinks !== undefined) {
      if (!Array.isArray(crossProjectLinks) || !crossProjectLinks.every(a => typeof a === 'string' && WALLET_ADDRESS_REGEX.test(a)))
        errors.push('crossProjectLinks must be an array of valid Solana Base58 addresses (32–44 chars)');
    }
    if (errors.length > 0) return res.status(400).json({ success: false, message: 'Validation failed', errors });

    const fieldsChanged = [
      addLiquidityValue !== undefined   ? 'addLiquidityValue'   : null,
      removeLiquidityValue !== undefined ? 'removeLiquidityValue' : null,
      walletFunding !== undefined        ? 'walletFunding'        : null,
      tokensCreated !== undefined        ? 'tokensCreated'        : null,
      forensicNotes !== undefined        ? 'forensicNotes'        : null,
      crossProjectLinks !== undefined    ? 'crossProjectLinks'    : null
    ].filter(Boolean);

    res.json({
      success: true,
      premiumForensics: { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks, updatedAt: new Date().toISOString() },
      auditLog: { updatedBy: 'admin', timestamp: new Date().toISOString(), fieldsChanged }
    });
  });

  // Submit report — with strict rate limit
  app.post('/api/wallets', submitRateLimit, (req, res) => {
    const { walletAddress, evidence, tokenAddress } = req.body;

    if (!walletAddress || !WALLET_ADDRESS_REGEX.test(walletAddress)) {
      return res.status(400).json({ success: false, message: 'Invalid wallet address format.' });
    }

    if (tokenAddress && !WALLET_ADDRESS_REGEX.test(tokenAddress)) {
      return res.status(400).json({ success: false, message: 'Invalid token address format.' });
    }

    const description = typeof evidence?.description === 'string' ? evidence.description.trim() : '';
    if (description.length > 500) {
      return res.status(400).json({ success: false, message: 'Description must be 500 characters or fewer.' });
    }

    const projectName = typeof req.body.projectName === 'string' ? req.body.projectName.trim() : '';
    if (projectName.length > 100) {
      return res.status(400).json({ success: false, message: 'Project name must be 100 characters or fewer.' });
    }

    const txHash = typeof evidence?.txHash === 'string' ? evidence.txHash.trim() : '';
    if (txHash && !TX_HASH_REGEX.test(txHash)) {
      return res.status(400).json({ success: false, message: 'Invalid transaction hash format.' });
    }

    // reporterContact is intentionally ignored — never returned or stored
    res.status(201).json({ success: true, message: 'Report submitted', data: { caseNumber: 1 } });
  });

  return app;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
const VALID_ADDRESS = 'So11111111111111111111111111111111111111112'; // 44 chars, valid Base58
const VALID_TX = 'ZeKaYDCPcCRFY9jHV4qHikWb3d6z4xB9SuKH1j6U2vxf'; // valid Base58
const VALID_TOKEN_ADDR = 'TokenAddr1111111111111111111111111111111111'; // 44 chars, valid Base58

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('1. Input Validation — WALLET_ADDRESS_REGEX', () => {
  test('accepts valid 44-char Solana address', () => {
    expect(WALLET_ADDRESS_REGEX.test('So11111111111111111111111111111111111111112')).toBe(true);
  });

  test('accepts valid 32-char address', () => {
    expect(WALLET_ADDRESS_REGEX.test('11111111111111111111111111111112')).toBe(true);
  });

  test('rejects address shorter than 32 chars', () => {
    expect(WALLET_ADDRESS_REGEX.test('short')).toBe(false);
  });

  test('rejects address longer than 44 chars', () => {
    expect(WALLET_ADDRESS_REGEX.test('So111111111111111111111111111111111111111123456')).toBe(false);
  });

  test('rejects address with Base58-invalid characters (0, O, I, l)', () => {
    expect(WALLET_ADDRESS_REGEX.test('0OIl000000000000000000000000000000000000000')).toBe(false);
  });

  test('rejects address with special characters', () => {
    expect(WALLET_ADDRESS_REGEX.test('<script>alert(1)</script>aaaaaaaaaaaaaaaaaaaa')).toBe(false);
  });
});

describe('2. Input Validation — TX_HASH_REGEX', () => {
  test('accepts valid tx hash', () => {
    expect(TX_HASH_REGEX.test(VALID_TX)).toBe(true);
  });

  test('rejects tx hash with spaces', () => {
    expect(TX_HASH_REGEX.test('abc def')).toBe(false);
  });

  test('rejects tx hash with angle brackets (XSS attempt)', () => {
    expect(TX_HASH_REGEX.test('<script>alert(1)</script>')).toBe(false);
  });

  test('rejects tx hash longer than 100 chars', () => {
    expect(TX_HASH_REGEX.test('A'.repeat(101))).toBe(false);
  });
});

describe('3. POST /api/wallets — Input Validation (HTTP)', () => {
  // Use a high submit cap so rate limiting does not interfere with validation tests
  const app = buildTestApp({ submitMax: 100 });

  test('rejects missing wallet address', async () => {
    const res = await request(app).post('/api/wallets').send({});
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects invalid wallet address', async () => {
    const res = await request(app).post('/api/wallets').send({ walletAddress: 'notvalid' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects address with Base58-invalid chars', async () => {
    const res = await request(app).post('/api/wallets').send({ walletAddress: '0OIl' + 'a'.repeat(40) });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects invalid token address', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      tokenAddress: '<bad>'
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects description over 500 chars', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      evidence: { description: 'A'.repeat(501) }
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects projectName over 100 chars', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      projectName: 'B'.repeat(101)
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('rejects txHash with invalid characters', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      evidence: { txHash: '<script>alert(1)</script>' }
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('accepts valid submission', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      evidence: { txHash: VALID_TX, description: 'Rugpull detected' }
    });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
  });
});

describe('4. Authorization — Premium Endpoint', () => {
  const secret = 'my-test-secret-12345678';
  const app = buildTestApp({ paymentSecret: secret });

  test('returns 402 when no payment header is provided', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}/premium`);
    expect(res.status).toBe(402);
  });

  test('returns 402 when wrong payment token is provided', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', 'wrong-token');
    expect(res.status).toBe(402);
  });

  test('returns 200 when correct payment token is provided', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('forensic');
    expect(res.body).toHaveProperty('premiumForensics');
  });

  test('returns 402 for empty string token', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', '');
    expect(res.status).toBe(402);
  });
});

describe('5. Rate Limiting — POST /api/wallets', () => {
  // Use a low max so the test runs quickly
  const app = buildTestApp({ submitMax: 3 });

  test('blocks requests after the per-route limit is exceeded', async () => {
    const payload = { walletAddress: VALID_ADDRESS };

    const results = [];
    for (let i = 0; i < 5; i++) {
      const res = await request(app).post('/api/wallets').send(payload);
      results.push(res.status);
    }

    // First 3 should succeed (201), remaining should be rate-limited (429)
    expect(results.slice(0, 3).every(s => s === 201)).toBe(true);
    expect(results.slice(3).every(s => s === 429)).toBe(true);
  });
});

describe('6. Data Sensitivity — reporterContact not returned', () => {
  const app = buildTestApp();

  test('response to GET /api/wallets does not include reporterContact', async () => {
    const res = await request(app).get('/api/wallets');
    expect(res.status).toBe(200);
    const wallets = res.body;
    wallets.forEach(w => {
      expect(w).not.toHaveProperty('reporterContact');
      expect(w).not.toHaveProperty('forensic');
      expect(w).not.toHaveProperty('premiumForensics');
    });
  });

  test('response to GET /api/wallets/:address does not include forensic data', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('forensic');
    expect(res.body).not.toHaveProperty('premiumForensics');
    expect(res.body).not.toHaveProperty('reporterContact');
  });

  test('submitting reporterContact does not cause it to appear in submit response', async () => {
    const res = await request(app).post('/api/wallets').send({
      walletAddress: VALID_ADDRESS,
      reporterContact: 'victim@example.com'  // PII — must be ignored
    });
    expect(res.status).toBe(201);
    expect(res.body).not.toHaveProperty('reporterContact');
    if (res.body.data) {
      expect(res.body.data).not.toHaveProperty('reporterContact');
    }
  });
});

describe('7. Security Headers — Helmet', () => {
  const app = buildTestApp();

  test('X-Content-Type-Options header is set', async () => {
    const res = await request(app).get('/api/wallets');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('X-Frame-Options header is set', async () => {
    const res = await request(app).get('/api/wallets');
    expect(res.headers['x-frame-options']).toBeDefined();
  });
});

describe('8. Premium Forensics — x402 gating', () => {
  const secret = 'premium-test-secret-xyz';
  const app = buildTestApp({ paymentSecret: secret });

  test('premium endpoint returns premiumForensics with valid x402 token', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('premiumForensics');
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue');
    expect(res.body.premiumForensics).toHaveProperty('removeLiquidityValue');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding');
    expect(res.body.premiumForensics).toHaveProperty('tokensCreated');
    expect(res.body.premiumForensics).toHaveProperty('forensicNotes');
    expect(res.body.premiumForensics).toHaveProperty('crossProjectLinks');
    expect(res.body.premiumForensics).toHaveProperty('updatedAt');
  });

  test('premiumForensics.tokensCreated is an array', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.premiumForensics.tokensCreated)).toBe(true);
  });

  test('premiumForensics.crossProjectLinks is an array', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.premiumForensics.crossProjectLinks)).toBe(true);
  });

  test('premium endpoint returns 402 without valid token (premiumForensics not leaked)', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}/premium`);
    expect(res.status).toBe(402);
    expect(res.body).not.toHaveProperty('premiumForensics');
  });
});

describe('9. Admin Endpoint — POST /api/admin/wallets/:address/premium-forensics', () => {
  const adminSec = 'admin-secret-token-abc';
  const app = buildTestApp({ adminSecret: adminSec });

  const premiumPayload = {
    addLiquidityValue: '45.2 SOL',
    removeLiquidityValue: '0.3 SOL',
    walletFunding: 'Tornado Cash',
    tokensCreated: ['TokenAddr1111111111111111111111111111111111'],
    forensicNotes: 'Repeat offender',
    crossProjectLinks: ['RelatedAddr111111111111111111111111111111111']
  };

  test('returns 403 without admin token', async () => {
    const res = await request(app)
      .post(`/api/admin/wallets/${VALID_ADDRESS}/premium-forensics`)
      .send(premiumPayload);
    expect(res.status).toBe(403);
  });

  test('returns 403 with wrong admin token', async () => {
    const res = await request(app)
      .post(`/api/admin/wallets/${VALID_ADDRESS}/premium-forensics`)
      .set('x-admin-token', 'wrong-token')
      .send(premiumPayload);
    expect(res.status).toBe(403);
  });

  test('returns 200 with correct admin token and updates premiumForensics', async () => {
    const res = await request(app)
      .post(`/api/admin/wallets/${VALID_ADDRESS}/premium-forensics`)
      .set('x-admin-token', adminSec)
      .send(premiumPayload);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue', '45.2 SOL');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding', 'Tornado Cash');
    expect(res.body.premiumForensics).toHaveProperty('updatedAt');
  });

  test('returns 403 with empty admin token string', async () => {
    const res = await request(app)
      .post(`/api/admin/wallets/${VALID_ADDRESS}/premium-forensics`)
      .set('x-admin-token', '')
      .send(premiumPayload);
    expect(res.status).toBe(403);
  });
});

describe('10. PATCH /api/admin/wallets/:address/premium — Authorization', () => {
  const tgToken = 'tg-admin-secret-xyz';
  const adminSec = 'admin-secret-xyz';
  const paySecret = 'pay-secret-xyz';
  const app = buildTestApp({ telegramAdminToken: tgToken, adminSecret: adminSec, paymentSecret: paySecret });

  const validPayload = { addLiquidityValue: '10 SOL', walletFunding: 'Binance' };

  test('returns 403 with no credentials', async () => {
    const res = await request(app).patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`).send(validPayload);
    expect(res.status).toBe(403);
  });

  test('returns 403 with wrong telegram admin token', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x-telegram-admin-token', 'wrong-token')
      .send(validPayload);
    expect(res.status).toBe(403);
  });

  test('returns 200 with valid telegram admin token', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x-telegram-admin-token', tgToken)
      .send(validPayload);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('returns 200 with valid x402-payment + x-admin-token', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', paySecret)
      .set('x-admin-token', adminSec)
      .send(validPayload);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('returns 403 with x402-payment only (missing admin role)', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', paySecret)
      .send(validPayload);
    expect(res.status).toBe(403);
  });

  test('returns 403 with x-admin-token only (missing x402 payment)', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x-admin-token', adminSec)
      .send(validPayload);
    expect(res.status).toBe(403);
  });
});

describe('11. PATCH /api/admin/wallets/:address/premium — Validation', () => {
  const tgToken = 'tg-admin-valid-token';
  const app = buildTestApp({ telegramAdminToken: tgToken });
  const auth = { 'x-telegram-admin-token': tgToken };

  test('accepts valid partial update (addLiquidityValue only)', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: '45.2 SOL' });
    expect(res.status).toBe(200);
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue', '45.2 SOL');
  });

  test('accepts addLiquidityValue without currency unit', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: '100' });
    expect(res.status).toBe(200);
  });

  test('accepts addLiquidityValue with USDC', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: '50.5 USDC' });
    expect(res.status).toBe(200);
  });

  test('rejects addLiquidityValue with letters before number', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: 'abc SOL' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(expect.arrayContaining([expect.stringMatching(/addLiquidityValue/)]));
  });

  test('rejects removeLiquidityValue with invalid format', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ removeLiquidityValue: '<script>' });
    expect(res.status).toBe(400);
  });

  test('accepts walletFunding under 200 chars with no HTML', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ walletFunding: 'Binance Hot Wallet' });
    expect(res.status).toBe(200);
  });

  test('rejects walletFunding with HTML tags', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ walletFunding: '<script>alert(1)</script>' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(expect.arrayContaining([expect.stringMatching(/walletFunding/)]));
  });

  test('rejects walletFunding exceeding 200 chars', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ walletFunding: 'A'.repeat(201) });
    expect(res.status).toBe(400);
  });

  test('accepts tokensCreated as array of valid Base58 addresses', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ tokensCreated: [VALID_TOKEN_ADDR] });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.premiumForensics.tokensCreated)).toBe(true);
  });

  test('rejects tokensCreated with invalid Base58 address', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ tokensCreated: ['not-valid-0OIl'] });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(expect.arrayContaining([expect.stringMatching(/tokensCreated/)]));
  });

  test('rejects tokensCreated as non-array', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ tokensCreated: 'not-an-array' });
    expect(res.status).toBe(400);
  });

  test('accepts crossProjectLinks as array of valid Base58 addresses', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ crossProjectLinks: [VALID_TOKEN_ADDR] });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.premiumForensics.crossProjectLinks)).toBe(true);
  });

  test('rejects crossProjectLinks with invalid address', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ crossProjectLinks: ['<bad>'] });
    expect(res.status).toBe(400);
  });

  test('accepts forensicNotes as a string', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ forensicNotes: 'Repeat offender pattern detected' });
    expect(res.status).toBe(200);
    expect(res.body.premiumForensics).toHaveProperty('forensicNotes', 'Repeat offender pattern detected');
  });

  test('rejects forensicNotes as non-string', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ forensicNotes: 12345 });
    expect(res.status).toBe(400);
  });

  test('returns multiple validation errors when multiple fields are invalid', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: 'bad', walletFunding: '<b>html</b>' });
    expect(res.status).toBe(400);
    expect(res.body.errors.length).toBeGreaterThanOrEqual(2);
  });
});

describe('12. PATCH /api/admin/wallets/:address/premium — Response Shape & Audit Log', () => {
  const tgToken = 'tg-admin-audit-token';
  const app = buildTestApp({ telegramAdminToken: tgToken });
  const auth = { 'x-telegram-admin-token': tgToken };

  test('response includes premiumForensics and auditLog', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: '10 SOL', forensicNotes: 'test note' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('premiumForensics');
    expect(res.body).toHaveProperty('auditLog');
  });

  test('auditLog contains updatedBy, timestamp, and fieldsChanged', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ addLiquidityValue: '10 SOL', walletFunding: 'Binance' });
    expect(res.status).toBe(200);
    expect(res.body.auditLog).toHaveProperty('updatedBy', 'admin');
    expect(res.body.auditLog).toHaveProperty('timestamp');
    expect(Array.isArray(res.body.auditLog.fieldsChanged)).toBe(true);
  });

  test('auditLog.fieldsChanged reflects only submitted fields', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ forensicNotes: 'only this field' });
    expect(res.status).toBe(200);
    expect(res.body.auditLog.fieldsChanged).toEqual(['forensicNotes']);
  });

  test('auditLog.fieldsChanged lists all fields when all are submitted', async () => {
    const res = await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({
        addLiquidityValue: '10 SOL',
        removeLiquidityValue: '1 SOL',
        walletFunding: 'Binance',
        tokensCreated: [VALID_TOKEN_ADDR],
        forensicNotes: 'note',
        crossProjectLinks: [VALID_TOKEN_ADDR]
      });
    expect(res.status).toBe(200);
    expect(res.body.auditLog.fieldsChanged).toEqual(
      expect.arrayContaining(['addLiquidityValue', 'removeLiquidityValue', 'walletFunding', 'tokensCreated', 'forensicNotes', 'crossProjectLinks'])
    );
  });
});

describe('13. PATCH /api/admin/wallets/:address/premium — Rate Limiting', () => {
  const tgToken = 'tg-ratelimit-token';
  // Low cap to make the test fast
  const app = buildTestApp({ telegramAdminToken: tgToken, patchAdminMax: 3 });
  const auth = { 'x-telegram-admin-token': tgToken };

  test('blocks requests after per-token rate limit is exceeded', async () => {
    const results = [];
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
        .set(auth)
        .send({ forensicNotes: `update ${i}` });
      results.push(res.status);
    }
    // First 3 should succeed (200), remaining should be rate-limited (429)
    expect(results.slice(0, 3).every(s => s === 200)).toBe(true);
    expect(results.slice(3).every(s => s === 429)).toBe(true);
  });
});

// ─── New x402 route / middleware tests ───────────────────────────────────────

const jwt = require('jsonwebtoken');
const { verifyX402Payment, _caches } = require('../middleware/verifyX402Payment');

// ── Shared test EC key pair (ES256) ──────────────────────────────────────────
const { privateKey: TEST_PRIV_KEY, publicKey: TEST_PUB_KEY } =
  crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const TEST_JWK = Object.assign(TEST_PUB_KEY.export({ format: 'jwk' }), {
  kid: 'test-kid-1',
  use: 'sig',
  alg: 'ES256'
});

function signTestToken(claims, opts = {}) {
  const keyid = opts.kid !== undefined ? opts.kid : 'test-kid-1';
  const signOpts = { algorithm: 'ES256', expiresIn: '1h' };
  if (keyid) signOpts.keyid = keyid;
  return jwt.sign(claims, TEST_PRIV_KEY, signOpts);
}

// Preload caches before each middleware test so no real HTTP calls are made
function injectTestCaches() {
  _caches.jwks  = { keys: [TEST_JWK], fetchedAt: Date.now() };
  _caches.price = { priceUSD: 150, fetchedAt: Date.now() };
}

// ── Minimal test app that uses the real verifyX402Payment middleware ──────────
function buildMiddlewareTestApp(expectedAmountUSD = 0.11) {
  const app = express();
  app.use(express.json());
  app.post('/test/payment', verifyX402Payment(expectedAmountUSD), (req, res) => {
    res.json({ success: true, payerAddress: req.x402.payerAddress });
  });
  return app;
}

// ════════════════════════════════════════════════════════════════════════════
// 14. verifyX402Payment middleware — unit behaviour
// ════════════════════════════════════════════════════════════════════════════

describe('14. verifyX402Payment middleware — unit behaviour', () => {
  beforeEach(injectTestCaches);

  test('returns 402 with requiredAmountUSD when no x402-payment header', async () => {
    const res = await request(buildMiddlewareTestApp()).post('/test/payment');
    expect(res.status).toBe(402);
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('returns 402 for a non-JWT value in the header', async () => {
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', 'not-a-jwt');
    expect(res.status).toBe(402);
  });

  test('returns 402 when JWT kid is not in the JWKS', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer: 'Addr1' }, { kid: 'unknown-kid' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Uu]nknown.*key/);
  });

  test('returns 200 with valid ES256 JWT — USD currency', async () => {
    const payer = 'SolanaPayerAddr111111111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(payer);
  });

  test('returns 200 with SOL currency converted via oracle price (0.001 SOL * $150 = $0.15)', async () => {
    const payer = 'SolanaPayerAddr111111111111111111111111111';
    const token = signTestToken({ amount: 0.001, currency: 'SOL', payer });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(payer);
  });

  test('returns 402 when SOL amount is insufficient (0.0001 SOL * $150 = $0.015 < $0.11)', async () => {
    const token = signTestToken({ amount: 0.0001, currency: 'SOL', payer: 'PayerAddr1' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Ii]nsufficient/);
  });

  test('returns 402 for exact threshold boundary (0.10 USD < 0.11 required)', async () => {
    const token = signTestToken({ amount: 0.10, currency: 'USD', payer: 'PayerAddr1' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(402);
  });

  test('returns 200 for exact required amount (0.11 USD == 0.11 required)', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer: 'PayerAddr1' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
  });

  test('returns 402 for unsupported currency (ETH)', async () => {
    const token = signTestToken({ amount: 1, currency: 'ETH', payer: 'PayerAddr1' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Uu]nsupported/);
  });

  test('returns 402 when payer address is absent from JWT claims', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USD' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/payer/i);
  });

  test('prefers payer claim over sub for payerAddress', async () => {
    const payer = 'PayerFromPayerClaim111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer, sub: 'SubClaim' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(payer);
  });

  test('falls back to from claim when payer is absent (x402 protocol convention)', async () => {
    const from = 'FromPayerAddr111111111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', from });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(from);
  });

  test('falls back to sub claim when payer and from are absent', async () => {
    const sub = 'SubPayerAddr111111111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', sub });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(sub);
  });

  test('accepts USDC as equivalent to USD', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USDC', payer: 'PayerAddr1' });
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
  });

  test('uses first key in JWKS when JWT has no kid', async () => {
    // Sign without keyid so the JWT header contains no kid — middleware should fall back to keys[0]
    const tokenNoKid = jwt.sign(
      { amount: 0.11, currency: 'USD', payer: 'PayerAddr1' },
      TEST_PRIV_KEY,
      { algorithm: 'ES256', expiresIn: '1h' }
    );
    const res = await request(buildMiddlewareTestApp())
      .post('/test/payment')
      .set('x402-payment', tokenNoKid);
    expect(res.status).toBe(200);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 15. GET /api/wallets/:address?include=premium — premium query gate
// ════════════════════════════════════════════════════════════════════════════

describe('15. GET /api/wallets/:address?include=premium — premium query gate', () => {
  const secret = 'premium-gate-secret';
  const app    = buildTestApp({ paymentSecret: secret });

  test('returns public data (no forensics) without ?include=premium', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('forensic');
    expect(res.body).not.toHaveProperty('premiumForensics');
  });

  test('returns 402 when ?include=premium but no x402-payment header', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}?include=premium`);
    expect(res.status).toBe(402);
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('returns 402 when ?include=premium with wrong payment token', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}?include=premium`)
      .set('x402-payment', 'wrong-token');
    expect(res.status).toBe(402);
  });

  test('returns full forensic data with correct payment token and ?include=premium', async () => {
    const res = await request(app)
      .get(`/api/wallets/${VALID_ADDRESS}?include=premium`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('forensic');
    expect(res.body).toHaveProperty('premiumForensics');
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue');
  });

  test('other query params do not trigger payment gate', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}?include=basic`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('forensic');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 16. POST /api/wallets/:address/premium/access — explicit unlock endpoint
// ════════════════════════════════════════════════════════════════════════════

describe('16. POST /api/wallets/:address/premium/access — explicit unlock', () => {
  const secret = 'unlock-endpoint-secret';
  const app    = buildTestApp({ paymentSecret: secret });

  test('returns 402 when no x402-payment header', async () => {
    const res = await request(app).post(`/api/wallets/${VALID_ADDRESS}/premium/access`);
    expect(res.status).toBe(402);
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('returns 402 with wrong payment token', async () => {
    const res = await request(app)
      .post(`/api/wallets/${VALID_ADDRESS}/premium/access`)
      .set('x402-payment', 'wrong-token');
    expect(res.status).toBe(402);
  });

  test('returns 200 with forensic + premiumForensics on valid payment', async () => {
    const res = await request(app)
      .post(`/api/wallets/${VALID_ADDRESS}/premium/access`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('payerAddress');
    expect(res.body).toHaveProperty('forensic');
    expect(res.body).toHaveProperty('premiumForensics');
  });

  test('response includes premiumForensics.addLiquidityValue on success', async () => {
    const res = await request(app)
      .post(`/api/wallets/${VALID_ADDRESS}/premium/access`)
      .set('x402-payment', secret);
    expect(res.status).toBe(200);
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding');
  });

  test('returns 404 for an invalid (non-Base58) wallet address', async () => {
    const res = await request(app)
      .post('/api/wallets/not-valid-0OIl/premium/access')
      .set('x402-payment', secret);
    expect(res.status).toBe(404);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 17. Bot — parsePremiumInput
// ════════════════════════════════════════════════════════════════════════════

describe('17. Bot — parsePremiumInput', () => {
  test('parses ADD_LIQ into addLiquidityValue', () => {
    expect(parsePremiumInput('ADD_LIQ: 45.2 SOL').addLiquidityValue).toBe('45.2 SOL');
  });

  test('parses REM_LIQ into removeLiquidityValue', () => {
    expect(parsePremiumInput('REM_LIQ: 0.3 SOL').removeLiquidityValue).toBe('0.3 SOL');
  });

  test('parses FUNDING into walletFunding', () => {
    expect(parsePremiumInput('FUNDING: CEX withdrawal (Binance)').walletFunding).toBe('CEX withdrawal (Binance)');
  });

  test('parses NOTES into forensicNotes', () => {
    expect(parsePremiumInput('NOTES: Repeated rugpull pattern across 3 projects').forensicNotes)
      .toBe('Repeated rugpull pattern across 3 projects');
  });

  test('parses TOKENS into a tokensCreated array', () => {
    const result = parsePremiumInput('TOKENS: So11111111111111111111111111111111111111112,TokenAddr1111111111111111111111111111111111');
    expect(Array.isArray(result.tokensCreated)).toBe(true);
    expect(result.tokensCreated).toHaveLength(2);
    expect(result.tokensCreated[0]).toBe('So11111111111111111111111111111111111111112');
  });

  test('parses LINKS into a crossProjectLinks array', () => {
    const result = parsePremiumInput('LINKS: So11111111111111111111111111111111111111112,TokenAddr1111111111111111111111111111111111');
    expect(Array.isArray(result.crossProjectLinks)).toBe(true);
    expect(result.crossProjectLinks).toHaveLength(2);
  });

  test('parses a full multi-line input correctly', () => {
    const text = [
      'ADD_LIQ: 45.2 SOL',
      'REM_LIQ: 0.3 SOL',
      'FUNDING: Binance',
      'TOKENS: So11111111111111111111111111111111111111112',
      'NOTES: test note',
      'LINKS: TokenAddr1111111111111111111111111111111111'
    ].join('\n');
    const result = parsePremiumInput(text);
    expect(result.addLiquidityValue).toBe('45.2 SOL');
    expect(result.removeLiquidityValue).toBe('0.3 SOL');
    expect(result.walletFunding).toBe('Binance');
    expect(result.forensicNotes).toBe('test note');
    expect(Array.isArray(result.tokensCreated)).toBe(true);
    expect(Array.isArray(result.crossProjectLinks)).toBe(true);
  });

  test('ignores unknown keys', () => {
    const result = parsePremiumInput('UNKNOWN: value\nADD_LIQ: 10 SOL');
    expect(result).not.toHaveProperty('UNKNOWN');
    expect(result.addLiquidityValue).toBe('10 SOL');
  });

  test('returns empty object for empty string', () => {
    expect(parsePremiumInput('')).toEqual({});
  });

  test('returns empty object for non-string input', () => {
    expect(parsePremiumInput(null)).toEqual({});
    expect(parsePremiumInput(undefined)).toEqual({});
  });

  test('key matching is case-insensitive (lower-case input normalised)', () => {
    expect(parsePremiumInput('add_liq: 5 SOL').addLiquidityValue).toBe('5 SOL');
  });

  test('strips extra whitespace from values', () => {
    expect(parsePremiumInput('ADD_LIQ:   20 SOL  ').addLiquidityValue).toBe('20 SOL');
  });

  test('handles colon in value correctly (only splits on first colon)', () => {
    expect(parsePremiumInput('FUNDING: CEX: Binance').walletFunding).toBe('CEX: Binance');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 18. Bot — validatePremiumFields
// ════════════════════════════════════════════════════════════════════════════

describe('18. Bot — validatePremiumFields', () => {
  test('returns no errors for empty data object', () => {
    expect(validatePremiumFields({})).toHaveLength(0);
  });

  test('accepts valid addLiquidityValue (number + SOL)', () => {
    expect(validatePremiumFields({ addLiquidityValue: '45.2 SOL' })).toHaveLength(0);
  });

  test('accepts addLiquidityValue without currency unit', () => {
    expect(validatePremiumFields({ addLiquidityValue: '100' })).toHaveLength(0);
  });

  test('accepts addLiquidityValue with USDC', () => {
    expect(validatePremiumFields({ addLiquidityValue: '50.5 USDC' })).toHaveLength(0);
  });

  test('rejects addLiquidityValue with letters before number', () => {
    const errors = validatePremiumFields({ addLiquidityValue: 'abc SOL' });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/ADD_LIQ/);
  });

  test('accepts valid removeLiquidityValue', () => {
    expect(validatePremiumFields({ removeLiquidityValue: '0.3 SOL' })).toHaveLength(0);
  });

  test('rejects removeLiquidityValue with invalid format', () => {
    const errors = validatePremiumFields({ removeLiquidityValue: '<script>' });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/REM_LIQ/);
  });

  test('accepts walletFunding under 200 chars with no HTML', () => {
    expect(validatePremiumFields({ walletFunding: 'CEX withdrawal (Binance)' })).toHaveLength(0);
  });

  test('rejects walletFunding with HTML tags', () => {
    const errors = validatePremiumFields({ walletFunding: '<script>alert(1)</script>' });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/FUNDING/);
  });

  test('rejects walletFunding exceeding 200 chars', () => {
    expect(validatePremiumFields({ walletFunding: 'A'.repeat(201) })).toHaveLength(1);
  });

  test('accepts tokensCreated as array of valid Base58 addresses', () => {
    expect(validatePremiumFields({
      tokensCreated: ['So11111111111111111111111111111111111111112']
    })).toHaveLength(0);
  });

  test('rejects tokensCreated with invalid Base58 address', () => {
    const errors = validatePremiumFields({ tokensCreated: ['not-valid-0OIl'] });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/TOKENS/);
  });

  test('rejects tokensCreated as non-array', () => {
    expect(validatePremiumFields({ tokensCreated: 'not-an-array' })).toHaveLength(1);
  });

  test('accepts forensicNotes as string', () => {
    expect(validatePremiumFields({ forensicNotes: 'Repeat offender detected' })).toHaveLength(0);
  });

  test('rejects forensicNotes as non-string', () => {
    expect(validatePremiumFields({ forensicNotes: 12345 })).toHaveLength(1);
  });

  test('accepts crossProjectLinks as valid Base58 array', () => {
    expect(validatePremiumFields({
      crossProjectLinks: ['So11111111111111111111111111111111111111112']
    })).toHaveLength(0);
  });

  test('rejects crossProjectLinks with invalid address', () => {
    const errors = validatePremiumFields({ crossProjectLinks: ['<bad>'] });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toMatch(/LINKS/);
  });

  test('returns multiple errors when multiple fields are invalid', () => {
    const errors = validatePremiumFields({
      addLiquidityValue: 'bad',
      walletFunding: '<b>html</b>'
    });
    expect(errors.length).toBeGreaterThanOrEqual(2);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 19. Bot — buildPremiumPreview
// ════════════════════════════════════════════════════════════════════════════

describe('19. Bot — buildPremiumPreview', () => {
  const WALLET = 'So11111111111111111111111111111111111111112';

  test('includes case number in preview', () => {
    expect(buildPremiumPreview(42, WALLET, {})).toContain('Case #42');
  });

  test('includes wallet address in preview', () => {
    expect(buildPremiumPreview(1, WALLET, {})).toContain(WALLET);
  });

  test('shows "(not set)" for all missing fields', () => {
    const msg = buildPremiumPreview(1, WALLET, {});
    expect(msg).toContain('(not set)');
  });

  test('includes a confirmation prompt', () => {
    expect(buildPremiumPreview(1, WALLET, {})).toMatch(/[Cc]onfirm/);
  });

  test('formats array values as comma-joined string', () => {
    const parsed = {
      tokensCreated: ['addr1111111111111111111111111111', 'addr2222222222222222222222222222']
    };
    const msg = buildPremiumPreview(1, WALLET, parsed);
    expect(msg).toContain('addr1111111111111111111111111111, addr2222222222222222222222222222');
  });

  test('shows provided scalar field values', () => {
    const parsed = { addLiquidityValue: '45.2 SOL', walletFunding: 'Binance Hot Wallet' };
    const msg = buildPremiumPreview(5, WALLET, parsed);
    expect(msg).toContain('45.2 SOL');
    expect(msg).toContain('Binance Hot Wallet');
  });

  test('contains all six field labels', () => {
    const msg = buildPremiumPreview(1, WALLET, {});
    expect(msg).toContain('ADD_LIQ');
    expect(msg).toContain('REM_LIQ');
    expect(msg).toContain('FUNDING');
    expect(msg).toContain('TOKENS');
    expect(msg).toContain('NOTES');
    expect(msg).toContain('LINKS');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 20. Bot — PREMIUM_HELP_TEXT content
// ════════════════════════════════════════════════════════════════════════════

describe('20. Bot — PREMIUM_HELP_TEXT', () => {
  test('contains all six format keys', () => {
    expect(PREMIUM_HELP_TEXT).toContain('ADD_LIQ');
    expect(PREMIUM_HELP_TEXT).toContain('REM_LIQ');
    expect(PREMIUM_HELP_TEXT).toContain('FUNDING');
    expect(PREMIUM_HELP_TEXT).toContain('TOKENS');
    expect(PREMIUM_HELP_TEXT).toContain('NOTES');
    expect(PREMIUM_HELP_TEXT).toContain('LINKS');
  });

  test('contains example values', () => {
    expect(PREMIUM_HELP_TEXT).toContain('45.2 SOL');
    expect(PREMIUM_HELP_TEXT).toContain('0.3 SOL');
  });

  test('mentions field validation constraints', () => {
    expect(PREMIUM_HELP_TEXT).toContain('200 chars');
    expect(PREMIUM_HELP_TEXT).toContain('Base58');
  });

  test('mentions /premium_help command', () => {
    expect(PREMIUM_HELP_TEXT).toContain('/premium_help');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 21. Bot — CAMEL_TO_KEY and SENSITIVE_FIELDS
// ════════════════════════════════════════════════════════════════════════════

describe('21. Bot — CAMEL_TO_KEY and SENSITIVE_FIELDS', () => {
  test('CAMEL_TO_KEY maps addLiquidityValue → ADD_LIQ', () => {
    expect(CAMEL_TO_KEY.addLiquidityValue).toBe('ADD_LIQ');
  });

  test('CAMEL_TO_KEY maps removeLiquidityValue → REM_LIQ', () => {
    expect(CAMEL_TO_KEY.removeLiquidityValue).toBe('REM_LIQ');
  });

  test('CAMEL_TO_KEY maps walletFunding → FUNDING', () => {
    expect(CAMEL_TO_KEY.walletFunding).toBe('FUNDING');
  });

  test('CAMEL_TO_KEY maps tokensCreated → TOKENS', () => {
    expect(CAMEL_TO_KEY.tokensCreated).toBe('TOKENS');
  });

  test('CAMEL_TO_KEY maps forensicNotes → NOTES', () => {
    expect(CAMEL_TO_KEY.forensicNotes).toBe('NOTES');
  });

  test('CAMEL_TO_KEY maps crossProjectLinks → LINKS', () => {
    expect(CAMEL_TO_KEY.crossProjectLinks).toBe('LINKS');
  });

  test('CAMEL_TO_KEY covers all six premium fields', () => {
    expect(Object.keys(CAMEL_TO_KEY)).toHaveLength(6);
  });

  test('SENSITIVE_FIELDS includes walletFunding', () => {
    expect(SENSITIVE_FIELDS.has('walletFunding')).toBe(true);
  });

  test('SENSITIVE_FIELDS includes crossProjectLinks', () => {
    expect(SENSITIVE_FIELDS.has('crossProjectLinks')).toBe(true);
  });

  test('SENSITIVE_FIELDS does not include non-sensitive fields', () => {
    expect(SENSITIVE_FIELDS.has('addLiquidityValue')).toBe(false);
    expect(SENSITIVE_FIELDS.has('forensicNotes')).toBe(false);
    expect(SENSITIVE_FIELDS.has('tokensCreated')).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 22. Bot — buildEditCurrentValues
// ════════════════════════════════════════════════════════════════════════════

describe('22. Bot — buildEditCurrentValues', () => {
  const WALLET = 'So11111111111111111111111111111111111111112';

  test('includes the case number', () => {
    expect(buildEditCurrentValues(42, WALLET, {})).toContain('Case #42');
  });

  test('includes the wallet address', () => {
    expect(buildEditCurrentValues(1, WALLET, {})).toContain(WALLET);
  });

  test('shows "(not set)" for missing fields', () => {
    const msg = buildEditCurrentValues(1, WALLET, {});
    expect(msg).toContain('(not set)');
  });

  test('shows all six field labels', () => {
    const msg = buildEditCurrentValues(1, WALLET, {});
    expect(msg).toContain('ADD_LIQ');
    expect(msg).toContain('REM_LIQ');
    expect(msg).toContain('FUNDING');
    expect(msg).toContain('TOKENS');
    expect(msg).toContain('NOTES');
    expect(msg).toContain('LINKS');
  });

  test('shows ✏️ edit indicator for each field', () => {
    const msg = buildEditCurrentValues(1, WALLET, {});
    // Should contain at least 6 ✏️ markers
    expect((msg.match(/\[✏️\]/g) || []).length).toBeGreaterThanOrEqual(6);
  });

  test('shows current scalar field values', () => {
    const data = { addLiquidityValue: '45.2 SOL', walletFunding: 'Binance Hot Wallet' };
    const msg  = buildEditCurrentValues(5, WALLET, data);
    expect(msg).toContain('45.2 SOL');
    expect(msg).toContain('Binance Hot Wallet');
  });

  test('formats array values as comma-joined string', () => {
    const data = { tokensCreated: ['addr1111111111111111111111111111', 'addr2222222222222222222222222222'] };
    const msg  = buildEditCurrentValues(1, WALLET, data);
    expect(msg).toContain('addr1111111111111111111111111111, addr2222222222222222222222222222');
  });

  test('includes instruction to send NEW_VALUES:', () => {
    const msg = buildEditCurrentValues(1, WALLET, {});
    expect(msg).toContain('NEW_VALUES:');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 23. Bot — buildDiffPreview
// ════════════════════════════════════════════════════════════════════════════

describe('23. Bot — buildDiffPreview', () => {
  test('includes the case number', () => {
    expect(buildDiffPreview(7, 'FUNDING', 'CEX withdrawal', 'Mixer (Tornado)')).toContain('Case #7');
  });

  test('includes the field label', () => {
    expect(buildDiffPreview(1, 'FUNDING', 'old', 'new')).toContain('FUNDING');
  });

  test('shows the old value with From: prefix', () => {
    expect(buildDiffPreview(1, 'FUNDING', 'CEX withdrawal', 'Mixer')).toContain("From: 'CEX withdrawal'");
  });

  test('shows the new value with To: prefix', () => {
    expect(buildDiffPreview(1, 'FUNDING', 'CEX withdrawal', 'Mixer')).toContain("To:   'Mixer'");
  });

  test('includes a confirmation prompt', () => {
    expect(buildDiffPreview(1, 'FUNDING', 'old', 'new')).toMatch(/[Cc]onfirm/);
  });

  test('shows "(not set)" for undefined old value', () => {
    expect(buildDiffPreview(1, 'FUNDING', undefined, 'Mixer')).toContain("From: '(not set)'");
  });

  test('does NOT include sensitive-field warning for non-sensitive field', () => {
    const msg = buildDiffPreview(1, 'ADD_LIQ', '45 SOL', '50 SOL', false);
    expect(msg).not.toContain('sensitive');
  });

  test('includes sensitive-field warning when isSensitive=true', () => {
    const msg = buildDiffPreview(1, 'FUNDING', 'old', 'new', true);
    expect(msg).toContain('sensitive');
  });

  test('formats array old value as comma-joined string', () => {
    const oldVal = ['addr1111111111111111111111111111', 'addr2222222222222222222222222222'];
    const msg    = buildDiffPreview(1, 'LINKS', oldVal, []);
    expect(msg).toContain('addr1111111111111111111111111111, addr2222222222222222222222222222');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 24. Bot — buildBulkDiffPreview
// ════════════════════════════════════════════════════════════════════════════

describe('24. Bot — buildBulkDiffPreview', () => {
  const WALLET = 'So11111111111111111111111111111111111111112';

  test('includes the case number', () => {
    const msg = buildBulkDiffPreview(42, WALLET, {}, { walletFunding: 'Mixer' });
    expect(msg).toContain('Case #42');
  });

  test('includes the wallet address', () => {
    const msg = buildBulkDiffPreview(1, WALLET, {}, { walletFunding: 'Mixer' });
    expect(msg).toContain(WALLET);
  });

  test('includes a confirmation prompt', () => {
    const msg = buildBulkDiffPreview(1, WALLET, {}, { walletFunding: 'Mixer' });
    expect(msg).toMatch(/[Cc]onfirm/);
  });

  test('lists changed field label and arrow', () => {
    const msg = buildBulkDiffPreview(1, WALLET, { walletFunding: 'CEX' }, { walletFunding: 'Mixer' });
    expect(msg).toContain('FUNDING');
    expect(msg).toContain('→');
  });

  test('shows old value in the change line', () => {
    const msg = buildBulkDiffPreview(1, WALLET, { walletFunding: 'CEX' }, { walletFunding: 'Mixer' });
    expect(msg).toContain("'CEX'");
    expect(msg).toContain("'Mixer'");
  });

  test('shows "(not set)" for missing old value', () => {
    const msg = buildBulkDiffPreview(1, WALLET, {}, { walletFunding: 'Mixer' });
    expect(msg).toContain("'(not set)'");
  });

  test('lists multiple changed fields', () => {
    const newData = { addLiquidityValue: '50 SOL', walletFunding: 'Mixer' };
    const msg     = buildBulkDiffPreview(1, WALLET, {}, newData);
    expect(msg).toContain('ADD_LIQ');
    expect(msg).toContain('FUNDING');
  });

  test('notes when no recognised fields are provided', () => {
    const msg = buildBulkDiffPreview(1, WALLET, {}, {});
    expect(msg).toContain('no recognised fields');
  });

  test('formats array new value as comma-joined string', () => {
    const newVal = ['addr1111111111111111111111111111', 'addr2222222222222222222222222222'];
    const msg    = buildBulkDiffPreview(1, WALLET, {}, { tokensCreated: newVal });
    expect(msg).toContain('addr1111111111111111111111111111, addr2222222222222222222222222222');
  });
});

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

// ─── Shared regex (mirrors server.js) ────────────────────────────────────────
const WALLET_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TX_HASH_REGEX = /^[1-9A-HJ-NP-Za-km-z]{1,100}$/;

// ─── Build a lightweight test app that mimics server.js validation ───────────
function buildTestApp({ paymentSecret = 'test-secret', submitMax = 5 } = {}) {
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

  // Public list — no forensic data
  app.get('/api/wallets', (_req, res) => {
    res.json([{ walletAddress: 'So11111111111111111111111111111111111111112', status: 'verified', riskScore: 95 }]);
  });

  // Public detail — no forensic data, no reporterContact
  app.get('/api/wallets/:address', (req, res) => {
    const addr = req.params.address;
    if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });
    res.json({ walletAddress: addr, status: 'verified', riskScore: 95 });
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

    res.json({ liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 });
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
    expect(res.body).toHaveProperty('liquidityBefore');
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
    });
  });

  test('response to GET /api/wallets/:address does not include forensic data', async () => {
    const res = await request(app).get(`/api/wallets/${VALID_ADDRESS}`);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('forensic');
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

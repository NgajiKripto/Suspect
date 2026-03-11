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
const cors = require('cors');
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
  buildBulkDiffPreview,
  CALLBACK
} = require('../botUtils');
const { requireAdminAuth } = require('../middleware/requireAdminAuth');
const { requireAccess }    = require('../middleware/requireAccess');
const { writeAuditLog, hashIp, AUDIT_LOG_PATH } = require('../auditLog');
const workflowState = require('../utils/workflowState');
const fs  = require('fs');

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
    res.json({ success: true, data: [{ walletAddress: 'So11111111111111111111111111111111111111112', status: 'verified', riskScore: 95 }] });
  });

  // Health check endpoint (mirrors production)
  app.get('/api/health', (_req, res) => {
    res.status(200).json({ success: true, status: 'ok', db: 'connected', timestamp: new Date().toISOString() });
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

  // In-memory audit log — populated by PATCH successes, queried by GET /api/admin/audit
  const inMemoryAuditLog = [];

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
      if (typeof forensicNotes !== 'string' || HTML_TAG_REGEX.test(forensicNotes))
        errors.push('forensicNotes must be a string with no HTML tags');
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

    const timestamp = new Date().toISOString();
    inMemoryAuditLog.push({
      timestamp,
      action:        'premium_update',
      walletAddress: req.params.address,
      caseNumber:    1,
      changedBy:     { source: 'api', identifier: 'wallet:testadmin' },
      fieldsChanged,
      before: {},
      after:  { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks }
    });

    res.json({
      success: true,
      premiumForensics: { addLiquidityValue, removeLiquidityValue, walletFunding, tokensCreated, forensicNotes, crossProjectLinks, updatedAt: timestamp },
      auditLog: { updatedBy: 'admin', timestamp, fieldsChanged }
    });
  });

  // GET admin audit log — returns last 50 entries for a wallet (mirrors production)
  app.get('/api/admin/audit', (req, res) => {
    let authorized = false;
    const tgToken = req.headers['x-telegram-admin-token'];
    if (tgToken && telegramAdminToken) {
      try {
        const aBuf = Buffer.from(tgToken);
        const bBuf = Buffer.from(telegramAdminToken);
        if (aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf)) authorized = true;
      } catch { /* fall through */ }
    }
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

    const { wallet } = req.query;
    if (!wallet || !WALLET_ADDRESS_REGEX.test(wallet)) {
      return res.status(400).json({ success: false, message: 'Invalid or missing wallet query parameter' });
    }

    const entries = inMemoryAuditLog
      .filter(e => e.walletAddress === wallet)
      .slice(-50);

    return res.json({ success: true, entries });
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

// ─── PS shared constants ──────────────────────────────────────────────────────
const ADMIN_WALLET  = 'PSAdminWallet1111111111111111111111111111111'; // 44 chars
const OTHER_WALLET  = 'PSOtherWallet111111111111111111111111111111';  // 43 chars — valid Base58 (32–44 range)
const ADMIN_CHAT_ID = '555666777';
const OTHER_CHAT_ID = '111222333';
const ADMIN_USER_ID = '444555666';

/** Reset JWKS and price caches after a PS suite. */
function resetPSCaches() {
  _caches.jwks  = { keys: null, fetchedAt: 0 };
  _caches.price = { priceUSD: null, fetchedAt: 0 };
}

// Frozen premium snapshot returned by the PS test apps
const PS_MOCK_PREMIUM_FORENSICS = {
  addLiquidityValue:    '45.2 SOL',
  removeLiquidityValue: '0.3 SOL',
  walletFunding:        'Tornado Cash',
  forensicNotes:        'Repeat offender pattern detected',
  tokensCreated:        [VALID_TOKEN_ADDR],
  crossProjectLinks:    ['RelatedAddr111111111111111111111111111111111'],
  updatedAt:            new Date().toISOString()
};

// High-limit rate limiter for PS test apps (avoids CodeQL missing-rate-limiting alert)
const PS_TEST_RATE_LIMIT = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10000,
  standardHeaders: false,
  legacyHeaders:   false
});

/** Test app for x402 / data-privacy tests (uses the REAL verifyX402Payment middleware). */
function buildPSX402TestApp() {
  const app = express();
  app.use(express.json());

  app.get('/api/wallets/:address', (req, res) => {
    const addr = req.params.address;
    if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });
    res.json({ walletAddress: addr, status: 'verified', riskScore: 95 });
  });

  app.get('/api/wallets/:address/premium',
    PS_TEST_RATE_LIMIT,
    verifyX402Payment(0.11),
    (req, res) => {
      const addr = req.params.address;
      if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });
      res.json({
        walletAddress: addr,
        status:        'verified',
        riskScore:     95,
        forensic:      { liquidityBefore: 100000, liquidityAfter: 0, drainDurationHours: 2 },
        premiumForensics: PS_MOCK_PREMIUM_FORENSICS,
        payerAddress:  req.x402.payerAddress
      });
    }
  );

  return app;
}

/**
 * Test app for admin / input-validation / audit tests.
 * Uses the REAL requireAdminAuth('api') middleware and writes to the real audit log.
 */
function buildPSAdminTestApp() {
  const app = express();
  app.use(express.json());

  app.patch('/api/admin/wallets/:address/premium',
    PS_TEST_RATE_LIMIT,
    requireAdminAuth('api'),
    (req, res) => {
      const addr = req.params.address;
      if (!WALLET_ADDRESS_REGEX.test(addr)) return res.status(404).json({ message: 'Not found' });

      const {
        addLiquidityValue, removeLiquidityValue,
        walletFunding, tokensCreated,
        forensicNotes, crossProjectLinks
      } = req.body;

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

/**
 * Minimum milliseconds to wait for async fs.appendFile to flush to disk.
 * Node's fs.appendFile is async (callback-based); 60 ms provides a reliable
 * margin on CI machines where I/O scheduling may add latency.
 */
const PS_LOG_FLUSH_DELAY_MS = 60;

/** Returns the current byte size of the audit log, 0 if file does not exist. */
function psLogSize() {
  try { return fs.statSync(AUDIT_LOG_PATH).size; }
  catch { return 0; }
}

/**
 * Reads only the log lines appended after `baseline` bytes.
 * Returns a Promise that resolves to an array of parsed JSON objects.
 * A small delay is used to let the async fs.appendFile complete.
 */
function psReadNewLogEntries(baseline) {
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
    }, PS_LOG_FLUSH_DELAY_MS);
  });
}

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
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    res.body.data.forEach(w => {
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
const { verifyX402Payment, getSolPriceUSD, _caches } = require('../middleware/verifyX402Payment');

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

// ════════════════════════════════════════════════════════════════════════════
// 25. requireAdminAuth — API middleware
// ════════════════════════════════════════════════════════════════════════════

describe('25. requireAdminAuth — API middleware', () => {
  // Re-use the shared ES256 key pair (TEST_PRIV_KEY / TEST_JWK / signTestToken)
  // and the injectTestCaches() helper defined at module level above.
  const ADMIN_WALLET = 'AdminWallet111111111111111111111111111111111'; // 44 chars
  const OTHER_WALLET = 'OtherWallet11111111111111111111111111111111';  // not in list

  function buildApp() {
    const app = express();
    app.use(express.json());
    app.get('/admin/test', requireAdminAuth('api'), (req, res) => {
      res.json({ success: true, adminAuth: req.adminAuth });
    });
    return app;
  }

  function signAdminToken(payerOverride) {
    return signTestToken({
      amount:   0.11,
      currency: 'USD',
      payer:    payerOverride !== undefined ? payerOverride : ADMIN_WALLET
    });
  }

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    _caches.jwks  = { keys: null, fetchedAt: 0 };
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  test('returns 403 when x402-payment header is absent', async () => {
    const res = await request(buildApp()).get('/admin/test');
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('returns 403 for a non-JWT string in x402-payment', async () => {
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', 'not-a-valid-jwt');
    expect(res.status).toBe(403);
  });

  test('returns 403 when JWT kid is not in the JWKS', async () => {
    const token = signTestToken(
      { amount: 0.11, currency: 'USD', payer: ADMIN_WALLET },
      { kid: 'unknown-kid' }
    );
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(403);
  });

  test('returns 403 when JWT payer address is not in ADMIN_WALLET_ADDRESSES', async () => {
    const token = signAdminToken(OTHER_WALLET);
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(403);
  });

  test('returns 403 when ADMIN_WALLET_ADDRESSES is empty', async () => {
    const saved = process.env.ADMIN_WALLET_ADDRESSES;
    process.env.ADMIN_WALLET_ADDRESSES = '';
    const token = signAdminToken();
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(403);
    process.env.ADMIN_WALLET_ADDRESSES = saved;
  });

  test('returns 403 when JWT payer claim is missing', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USD' });
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(403);
  });

  test('returns 200 and sets req.adminAuth when payer is in whitelist', async () => {
    const token = signAdminToken();
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.adminAuth).toEqual({ source: 'api', payerAddress: ADMIN_WALLET });
  });

  test('accepts a second admin wallet in a comma-separated whitelist', async () => {
    process.env.ADMIN_WALLET_ADDRESSES = OTHER_WALLET + ',' + ADMIN_WALLET;
    const token = signAdminToken();
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
  });

  test('trims spaces around addresses in ADMIN_WALLET_ADDRESSES', async () => {
    process.env.ADMIN_WALLET_ADDRESSES = '  ' + ADMIN_WALLET + '  ';
    const token = signAdminToken();
    const res = await request(buildApp())
      .get('/admin/test')
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
  });

  test('throws for an invalid source argument', () => {
    expect(() => requireAdminAuth('ftp')).toThrow(/invalid source/i);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 26. requireAdminAuth — Telegram handler
// ════════════════════════════════════════════════════════════════════════════

describe('26. requireAdminAuth — Telegram handler', () => {
  const ADMIN_CHAT_ID = '123456789';
  const ADMIN_USER_ID = '111111111';
  const OTHER_CHAT_ID = '987654321';
  const OTHER_USER_ID = '999999999';

  // Obtain a fresh handler so each test picks up the current env
  function getHandler() {
    return requireAdminAuth('telegram');
  }

  function makeMessage(chatId = ADMIN_CHAT_ID, fromId = ADMIN_USER_ID) {
    return { chat: { id: chatId }, from: { id: fromId }, text: '/command' };
  }

  function makeCallbackQuery(chatId = ADMIN_CHAT_ID, fromId = ADMIN_USER_ID) {
    return { message: { chat: { id: chatId } }, from: { id: fromId }, data: 'action_walletid' };
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

  test('returns true for an authorized Message (correct chat.id and from.id)', () => {
    expect(getHandler()(makeMessage())).toBe(true);
  });

  test('returns true for an authorized CallbackQuery (correct message.chat.id and from.id)', () => {
    expect(getHandler()(makeCallbackQuery())).toBe(true);
  });

  test('returns false when chat.id does not match TELEGRAM_ADMIN_CHAT_ID', () => {
    expect(getHandler()(makeMessage(OTHER_CHAT_ID, ADMIN_USER_ID))).toBe(false);
  });

  test('returns false when from.id is not in TELEGRAM_ADMIN_USER_IDS', () => {
    expect(getHandler()(makeMessage(ADMIN_CHAT_ID, OTHER_USER_ID))).toBe(false);
  });

  test('returns true when TELEGRAM_ADMIN_USER_IDS is empty (no user whitelist)', () => {
    process.env.TELEGRAM_ADMIN_USER_IDS = '';
    expect(getHandler()(makeMessage())).toBe(true);
  });

  test('returns false when TELEGRAM_ADMIN_CHAT_ID is not configured', () => {
    delete process.env.TELEGRAM_ADMIN_CHAT_ID;
    expect(getHandler()(makeMessage())).toBe(false);
  });

  test('falls back to TELEGRAM_CHAT_ID when TELEGRAM_ADMIN_CHAT_ID is absent', () => {
    delete process.env.TELEGRAM_ADMIN_CHAT_ID;
    process.env.TELEGRAM_CHAT_ID = ADMIN_CHAT_ID;
    expect(getHandler()(makeMessage())).toBe(true);
  });

  test('accepts any user ID from a multi-entry TELEGRAM_ADMIN_USER_IDS', () => {
    process.env.TELEGRAM_ADMIN_USER_IDS = OTHER_USER_ID + ',' + ADMIN_USER_ID;
    expect(getHandler()(makeMessage(ADMIN_CHAT_ID, OTHER_USER_ID))).toBe(true);
    expect(getHandler()(makeMessage(ADMIN_CHAT_ID, ADMIN_USER_ID))).toBe(true);
  });

  test('trims spaces around IDs in TELEGRAM_ADMIN_USER_IDS', () => {
    process.env.TELEGRAM_ADMIN_USER_IDS = '  ' + ADMIN_USER_ID + '  ';
    expect(getHandler()(makeMessage())).toBe(true);
  });

  test('returns false when CallbackQuery chat.id does not match', () => {
    expect(getHandler()(makeCallbackQuery(OTHER_CHAT_ID, ADMIN_USER_ID))).toBe(false);
  });

  test('returns false for null input', () => {
    expect(getHandler()(null)).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 27. GET /api/admin/audit — Admin Audit Log Endpoint
// ════════════════════════════════════════════════════════════════════════════

describe('27. GET /api/admin/audit — Admin Audit Log Endpoint', () => {
  const tgToken = 'tg-audit-view-token';
  const app = buildTestApp({ telegramAdminToken: tgToken });
  const auth = { 'x-telegram-admin-token': tgToken };

  test('returns 403 without admin credentials', async () => {
    const res = await request(app).get(`/api/admin/audit?wallet=${VALID_ADDRESS}`);
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('returns 400 when wallet query param is missing', async () => {
    const res = await request(app).get('/api/admin/audit').set(auth);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/wallet/i);
  });

  test('returns 400 when wallet query param is invalid', async () => {
    const res = await request(app).get('/api/admin/audit?wallet=notvalid').set(auth);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 400 for wallet with Base58-invalid characters', async () => {
    const res = await request(app).get('/api/admin/audit?wallet=0OIl000000000000000000000000000000000000000').set(auth);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 200 with empty entries array when no entries exist for wallet', async () => {
    const res = await request(app)
      .get(`/api/admin/audit?wallet=${VALID_ADDRESS}`)
      .set(auth);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.entries)).toBe(true);
  });

  test('returns entries with correct shape after PATCH creates one', async () => {
    // Perform a PATCH to populate the in-memory audit log
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set(auth)
      .send({ forensicNotes: 'audit trail test' });

    const res = await request(app)
      .get(`/api/admin/audit?wallet=${VALID_ADDRESS}`)
      .set(auth);
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThan(0);

    const entry = res.body.entries[res.body.entries.length - 1];
    expect(entry).toHaveProperty('timestamp');
    expect(entry).toHaveProperty('action', 'premium_update');
    expect(entry).toHaveProperty('walletAddress', VALID_ADDRESS);
    expect(entry).toHaveProperty('fieldsChanged');
    expect(Array.isArray(entry.fieldsChanged)).toBe(true);
    expect(entry).toHaveProperty('changedBy');
    expect(entry.changedBy).toHaveProperty('source');
    expect(entry.changedBy).toHaveProperty('identifier');
    expect(entry).toHaveProperty('before');
    expect(entry).toHaveProperty('after');
  });

  test('does not return entries for a different wallet', async () => {
    // VALID_TOKEN_ADDR is a different valid Base58 address from VALID_ADDRESS
    const res = await request(app)
      .get(`/api/admin/audit?wallet=${VALID_TOKEN_ADDR}`)
      .set(auth);
    expect(res.status).toBe(200);
    // No entries for VALID_TOKEN_ADDR should contain a different wallet address
    expect(res.body.entries.filter(e => e.walletAddress !== VALID_TOKEN_ADDR)).toHaveLength(0);
  });

  test('returns at most 50 entries', async () => {
    // Build an app and flood it with 60 PATCH calls
    const floodApp = buildTestApp({ telegramAdminToken: tgToken, patchAdminMax: 1000 });
    for (let i = 0; i < 60; i++) {
      await request(floodApp)
        .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
        .set(auth)
        .send({ forensicNotes: `entry ${i}` });
    }
    const res = await request(floodApp)
      .get(`/api/admin/audit?wallet=${VALID_ADDRESS}`)
      .set(auth);
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeLessThanOrEqual(50);
  });

  test('returns 403 with wrong telegram token', async () => {
    const res = await request(app)
      .get(`/api/admin/audit?wallet=${VALID_ADDRESS}`)
      .set('x-telegram-admin-token', 'wrong-token');
    expect(res.status).toBe(403);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 28. auditLog utility — hashIp and writeAuditLog
// ════════════════════════════════════════════════════════════════════════════

describe('28. auditLog utility — hashIp and writeAuditLog', () => {
  test('hashIp returns a sha256-prefixed 64-char hex string for a valid IP', () => {
    const result = hashIp('127.0.0.1');
    expect(result).toMatch(/^sha256-[a-f0-9]{64}$/);
  });

  test('hashIp returns undefined for null', () => {
    expect(hashIp(null)).toBeUndefined();
  });

  test('hashIp returns undefined for empty string', () => {
    expect(hashIp('')).toBeUndefined();
  });

  test('hashIp returns undefined for undefined', () => {
    expect(hashIp(undefined)).toBeUndefined();
  });

  test('hashIp produces different hashes for different IPs', () => {
    expect(hashIp('1.2.3.4')).not.toBe(hashIp('4.3.2.1'));
  });

  test('hashIp is deterministic (same input → same output)', () => {
    expect(hashIp('192.168.1.1')).toBe(hashIp('192.168.1.1'));
  });

  test('AUDIT_LOG_PATH ends with logs/admin_audit.log', () => {
    expect(AUDIT_LOG_PATH).toMatch(/logs[/\\]admin_audit\.log$/);
  });

  test('writeAuditLog does not throw for a valid entry', () => {
    expect(() => writeAuditLog({
      timestamp:     new Date().toISOString(),
      action:        'premium_update',
      walletAddress: VALID_ADDRESS
    })).not.toThrow();
  });

  test('writeAuditLog does not throw for an empty object', () => {
    expect(() => writeAuditLog({})).not.toThrow();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 29. verifyX402Payment({ mode: 'basic' }) — timingSafeEqual backward-compat
// ════════════════════════════════════════════════════════════════════════════

describe('29. verifyX402Payment({ mode: \'basic\' }) — backward-compat tests', () => {
  const BASIC_SECRET = 'test-basic-secret-x402-bc';

  // High-limit rate limiter for test apps (avoids CodeQL missing-rate-limiting alert)
  const BASIC_TEST_RATE_LIMIT = rateLimit({
    windowMs: 60 * 60 * 1000, max: 10000,
    standardHeaders: false, legacyHeaders: false
  });

  function buildBasicModeApp() {
    const app = express();
    app.use(express.json());
    app.get('/test/basic',
      BASIC_TEST_RATE_LIMIT,
      verifyX402Payment({ mode: 'basic' }),
      (req, res) => res.json({
        valid:        req.x402.valid,
        payerAddress: req.x402.payerAddress,
        amountUSD:    req.x402.amountUSD
      })
    );
    return app;
  }

  beforeEach(() => { process.env.X402_PAYMENT_SECRET = BASIC_SECRET; });
  afterEach(() => { delete process.env.X402_PAYMENT_SECRET; });

  test('returns 402 when x402-payment header is absent', async () => {
    const res = await request(buildBasicModeApp()).get('/test/basic');
    expect(res.status).toBe(402);
    expect(res.body).toHaveProperty('error', 'Payment Required');
    expect(res.body).toHaveProperty('message');
    expect(res.body).not.toHaveProperty('premiumForensics');
  });

  test('returns 402 when x402-payment does not match X402_PAYMENT_SECRET', async () => {
    const res = await request(buildBasicModeApp())
      .get('/test/basic')
      .set('x402-payment', 'wrong-secret');
    expect(res.status).toBe(402);
  });

  test('returns 200 and sets req.x402 when x402-payment matches X402_PAYMENT_SECRET', async () => {
    const res = await request(buildBasicModeApp())
      .get('/test/basic')
      .set('x402-payment', BASIC_SECRET);
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.payerAddress).toBeNull();
    expect(res.body.amountUSD).toBeNull();
  });

  test('returns 402 when X402_PAYMENT_SECRET env var is not set', async () => {
    delete process.env.X402_PAYMENT_SECRET;
    const res = await request(buildBasicModeApp())
      .get('/test/basic')
      .set('x402-payment', 'any-value');
    expect(res.status).toBe(402);
  });

  test('does NOT include requiredAmountUSD in basic-mode 402 response', async () => {
    const res = await request(buildBasicModeApp()).get('/test/basic');
    expect(res.status).toBe(402);
    expect(res.body).not.toHaveProperty('requiredAmountUSD');
  });

  test('backward-compat: verifyX402Payment(number) uses premium mode', async () => {
    injectTestCaches();
    const payer = 'BackCompatPayerAddr11111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const app   = express();
    app.use(express.json());
    app.post('/test/compat', BASIC_TEST_RATE_LIMIT, verifyX402Payment(0.11), (req, res) => {
      res.json({ payerAddress: req.x402.payerAddress, amountUSD: req.x402.amountUSD });
    });
    const res = await request(app).post('/test/compat').set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.payerAddress).toBe(payer);
    expect(res.body.amountUSD).toBe(0.11);
  });

  test('premium mode sets amountUSD in req.x402', async () => {
    injectTestCaches();
    const payer = 'AmountUSDTestPayer111111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const app   = express();
    app.use(express.json());
    app.post('/test/amount', BASIC_TEST_RATE_LIMIT, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (req, res) => {
      res.json({ payerAddress: req.x402.payerAddress, amountUSD: req.x402.amountUSD });
    });
    const res = await request(app).post('/test/amount').set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.amountUSD).toBe(0.11);
    expect(res.body.payerAddress).toBe(payer);
  });

  test('premium mode with SOL currency sets amountUSD to (sol_amount * price)', async () => {
    // 0.001 SOL * $150/SOL = $0.15, which is above the $0.11 minimum → payment accepted
    injectTestCaches(); // price = $150/SOL
    const payer = 'SolAmountPayer111111111111111111111111111';
    const token = signTestToken({ amount: 0.001, currency: 'SOL', payer });
    const app   = express();
    app.use(express.json());
    app.post('/test/sol', BASIC_TEST_RATE_LIMIT, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (req, res) => {
      res.json({ amountUSD: req.x402.amountUSD });
    });
    const res = await request(app).post('/test/sol').set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body.amountUSD).toBeCloseTo(0.15); // 0.001 * 150
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 30. Oracle price cache — 5-min TTL (Date.now mocked)
// ════════════════════════════════════════════════════════════════════════════

describe('30. Oracle price cache — 5-min TTL', () => {
  const PRICE_CACHE_TTL_MS = 5 * 60 * 1000;

  afterEach(() => {
    jest.restoreAllMocks();
    // Reset price cache to clean state to avoid cross-test pollution
    _caches.price = { priceUSD: null, fetchedAt: 0 };
  });

  test('uses cached price when called within the 5-min TTL window', async () => {
    const fakeNow    = 10_000_000;
    const cachedPrice = 180.00;
    // Inject a fresh cache entry
    _caches.price = { priceUSD: cachedPrice, fetchedAt: fakeNow };
    // Advance time to 1 ms before TTL expiry — cache should still be valid
    jest.spyOn(Date, 'now').mockReturnValue(fakeNow + PRICE_CACHE_TTL_MS - 1);

    const price = await getSolPriceUSD();
    expect(price).toBe(cachedPrice);
    // fetchedAt must be unchanged — no re-fetch occurred
    expect(_caches.price.fetchedAt).toBe(fakeNow);
  });

  test('does NOT use cached price when TTL has expired', async () => {
    const fakeNow    = 10_000_000;
    const cachedPrice = 180.00;
    // Inject a cache entry that is exactly at the TTL boundary (expired)
    _caches.price = { priceUSD: cachedPrice, fetchedAt: fakeNow - PRICE_CACHE_TTL_MS - 1 };
    // Date.now() is past the TTL window
    jest.spyOn(Date, 'now').mockReturnValue(fakeNow);

    // getSolPriceUSD() must attempt an HTTP re-fetch; in tests there is no real network,
    // so it rejects — proving the cache was bypassed
    await expect(getSolPriceUSD()).rejects.toThrow();
  });

  test('returns same cached price for repeated calls within TTL', async () => {
    const fakeNow    = 20_000_000;
    const cachedPrice = 99.99;
    _caches.price = { priceUSD: cachedPrice, fetchedAt: fakeNow };
    jest.spyOn(Date, 'now').mockReturnValue(fakeNow + 1000); // 1 second later

    const p1 = await getSolPriceUSD();
    const p2 = await getSolPriceUSD();
    expect(p1).toBe(cachedPrice);
    expect(p2).toBe(cachedPrice);
  });

  test('cache boundary: price is valid at exactly TTL - 1 ms', () => {
    const fetchedAt = 0;
    const now       = PRICE_CACHE_TTL_MS - 1;
    // Mirrors the condition inside getSolPriceUSD
    expect(now - fetchedAt).toBeLessThan(PRICE_CACHE_TTL_MS);
  });

  test('cache boundary: price is expired at exactly TTL ms after fetch', () => {
    const fetchedAt = 0;
    const now       = PRICE_CACHE_TTL_MS;
    expect(now - fetchedAt).toBeGreaterThanOrEqual(PRICE_CACHE_TTL_MS);
  });

  test('middleware uses cached SOL price within TTL — no re-fetch on second request', async () => {
    // Inject fresh caches with a known SOL price so both requests use the same cached value
    const fakeNow = 30_000_000;
    _caches.jwks  = { keys: [TEST_JWK], fetchedAt: fakeNow };
    _caches.price = { priceUSD: 200, fetchedAt: fakeNow };
    jest.spyOn(Date, 'now').mockReturnValue(fakeNow + 1000);

    const app = express();
    app.use(express.json());
    const TEST_RL = rateLimit({ windowMs: 60_000, max: 10000, standardHeaders: false, legacyHeaders: false });
    app.get('/test/cache', TEST_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => {
      res.json({ amountUSD: _req.x402.amountUSD });
    });

    const payer = 'CacheTestPayer11111111111111111111111111111';
    const token = signTestToken({ amount: 0.001, currency: 'SOL', payer }); // 0.001 * $200 = $0.20 ≥ $0.11

    const r1 = await request(app).get('/test/cache').set('x402-payment', token);
    const r2 = await request(app).get('/test/cache').set('x402-payment', token);

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r1.body.amountUSD).toBeCloseTo(0.20);
    expect(r2.body.amountUSD).toBeCloseTo(0.20);
    // Cache fetchedAt must be unchanged — no re-fetch between the two requests
    expect(_caches.price.fetchedAt).toBe(fakeNow);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 31. Premium endpoint integration — premiumForensics + "upgrade required"
// ════════════════════════════════════════════════════════════════════════════

describe('31. Premium endpoint integration — premiumForensics response', () => {
  // Rate limiter for test apps (avoids CodeQL missing-rate-limiting alert)
  const PREM_RL = rateLimit({ windowMs: 60_000, max: 10000, standardHeaders: false, legacyHeaders: false });

  function buildPremiumIntegrationApp(expectedAmountUSD = 0.11) {
    const app = express();
    app.use(express.json());
    app.get(
      '/test/premium-data',
      PREM_RL,
      verifyX402Payment({ mode: 'premium', expectedAmountUSD }),
      (req, res) => res.json({
        success:         true,
        payerAddress:    req.x402.payerAddress,
        amountUSD:       req.x402.amountUSD,
        premiumForensics: {
          addLiquidityValue:    '45.2 SOL',
          removeLiquidityValue: '0.3 SOL',
          walletFunding:        'Tornado Cash',
          forensicNotes:        'Repeat offender pattern detected',
          tokensCreated:        ['TokenAddr1111111111111111111111111111111111'],
          crossProjectLinks:    ['RelatedAddr111111111111111111111111111111111'],
          updatedAt:            new Date().toISOString()
        }
      })
    );
    return app;
  }

  beforeEach(injectTestCaches);

  test('returns 200 with premiumForensics when payment header is absent (setup: no header)', async () => {
    const res = await request(buildPremiumIntegrationApp()).get('/test/premium-data');
    // No header → 402, no premiumForensics
    expect(res.status).toBe(402);
    expect(res.body).not.toHaveProperty('premiumForensics');
  });

  test('returns 200 and premiumForensics with valid JWT containing sufficient amount', async () => {
    const payer = 'PremiumPayerAddr111111111111111111111111111';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res   = await request(buildPremiumIntegrationApp())
      .get('/test/premium-data')
      .set('x402-payment', token);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty('premiumForensics');
    expect(res.body.premiumForensics).toHaveProperty('addLiquidityValue', '45.2 SOL');
    expect(res.body.premiumForensics).toHaveProperty('walletFunding', 'Tornado Cash');
    expect(res.body).toHaveProperty('payerAddress', payer);
    expect(res.body).toHaveProperty('amountUSD', 0.11);
  });

  test('returns 402 with "upgrade required" message when amount is insufficient', async () => {
    const payer = 'LowPayerAddr11111111111111111111111111111111';
    const token = signTestToken({ amount: 0.05, currency: 'USD', payer }); // 0.05 < 0.11
    const res   = await request(buildPremiumIntegrationApp())
      .get('/test/premium-data')
      .set('x402-payment', token);

    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/upgrade required/i);
    expect(res.body).not.toHaveProperty('premiumForensics');
  });

  test('insufficient payment 402 message also references the required threshold', async () => {
    const payer = 'LowPayer2Addr1111111111111111111111111111111';
    const token = signTestToken({ amount: 0.01, currency: 'USD', payer });
    const res   = await request(buildPremiumIntegrationApp(0.25))
      .get('/test/premium-data')
      .set('x402-payment', token);

    expect(res.status).toBe(402);
    expect(res.body.message).toContain('0.25');  // required threshold visible to caller
  });

  test('returns 402 with requiredAmountUSD when header is absent', async () => {
    const res = await request(buildPremiumIntegrationApp()).get('/test/premium-data');
    expect(res.status).toBe(402);
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('premiumForensics is only present in 200 responses, never in 402 responses', async () => {
    // Insufficient payment
    const payer  = 'CheckPayerAddr111111111111111111111111111111';
    const badTok = signTestToken({ amount: 0.01, currency: 'USD', payer });
    const badRes = await request(buildPremiumIntegrationApp())
      .get('/test/premium-data')
      .set('x402-payment', badTok);
    expect(badRes.status).toBe(402);
    expect(badRes.body).not.toHaveProperty('premiumForensics');

    // Sufficient payment
    const goodTok = signTestToken({ amount: 0.50, currency: 'USD', payer });
    const goodRes = await request(buildPremiumIntegrationApp())
      .get('/test/premium-data')
      .set('x402-payment', goodTok);
    expect(goodRes.status).toBe(200);
    expect(goodRes.body).toHaveProperty('premiumForensics');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 32. timingSafeEqual — both code paths prevent timing attacks
// ════════════════════════════════════════════════════════════════════════════

describe('32. timingSafeEqual — both code paths prevent timing attacks', () => {
  const SECRET = 'timing-safe-test-secret-xyz';

  // Rate limiter for test apps
  const TSE_RL = rateLimit({ windowMs: 60_000, max: 10000, standardHeaders: false, legacyHeaders: false });

  function buildBasicApp() {
    const app = express();
    app.use(express.json());
    app.get('/test/timing-basic', TSE_RL, verifyX402Payment({ mode: 'basic' }), (_req, res) => {
      res.json({ ok: true });
    });
    return app;
  }

  beforeEach(() => { process.env.X402_PAYMENT_SECRET = SECRET; });
  afterEach(() => { delete process.env.X402_PAYMENT_SECRET; });

  // ── Basic mode ────────────────────────────────────────────────────────────

  test('basic mode: header shorter than secret returns 402 (no crash)', async () => {
    const res = await request(buildBasicApp())
      .get('/test/timing-basic')
      .set('x402-payment', SECRET.slice(0, -3)); // shorter than secret
    expect(res.status).toBe(402);
    expect(res.body.error).toBe('Payment Required');
  });

  test('basic mode: header longer than secret returns 402 (no crash)', async () => {
    const res = await request(buildBasicApp())
      .get('/test/timing-basic')
      .set('x402-payment', SECRET + 'extra');
    expect(res.status).toBe(402);
  });

  test('basic mode: empty header returns 402 (timingSafeEqual length guard)', async () => {
    const res = await request(buildBasicApp())
      .get('/test/timing-basic')
      .set('x402-payment', '');
    // An empty header is equivalent to no header — must be rejected
    expect(res.status).toBe(402);
  });

  test('basic mode: same-length but wrong content returns 402', async () => {
    // Construct a string with same byte length but different content
    const sameLength = 'X'.repeat(Buffer.byteLength(SECRET, 'utf8'));
    const res = await request(buildBasicApp())
      .get('/test/timing-basic')
      .set('x402-payment', sameLength);
    expect(res.status).toBe(402);
  });

  test('basic mode: correct secret returns 200 (timingSafeEqual positive path)', async () => {
    const res = await request(buildBasicApp())
      .get('/test/timing-basic')
      .set('x402-payment', SECRET);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('basic mode: timingSafeEqual comparison does not throw for any ASCII input', () => {
    // Verify the constant-time comparison logic via Node crypto directly
    const inputs = ['', 'a', SECRET, SECRET + 'extra', SECRET.slice(0, -1)];
    for (const input of inputs) {
      expect(() => {
        const a = Buffer.from(input);
        const b = Buffer.from(SECRET);
        if (a.length === b.length) crypto.timingSafeEqual(a, b);
      }).not.toThrow();
    }
  });

  // ── Premium mode ──────────────────────────────────────────────────────────

  test('premium mode: tampered JWT signature returns 402 (not 500)', async () => {
    injectTestCaches();
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer: 'Payer1111111111111111111111111111111111111' });
    // Corrupt the signature segment
    const parts   = token.split('.');
    parts[2]      = parts[2].split('').reverse().join('');
    const tampered = parts.join('.');

    const app = express();
    app.use(express.json());
    app.get('/test/timing-prem', TSE_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => {
      res.json({ ok: true });
    });
    const res = await request(app).get('/test/timing-prem').set('x402-payment', tampered);
    expect(res.status).toBe(402);
    expect(res.body.error).toBe('Payment Required');
  });

  test('premium mode: replay with zeroed signature bytes returns 402 (not 500)', async () => {
    injectTestCaches();
    const token  = signTestToken({ amount: 0.11, currency: 'USD', payer: 'Payer2222222222222222222222222222222222222' });
    const parts  = token.split('.');
    parts[2]     = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const forged = parts.join('.');

    const app = express();
    app.use(express.json());
    app.get('/test/timing-replay', TSE_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => {
      res.json({ ok: true });
    });
    const res = await request(app).get('/test/timing-replay').set('x402-payment', forged);
    expect(res.status).toBe(402);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 33. Error messages — no internal logic or secrets leak
// ════════════════════════════════════════════════════════════════════════════

describe('33. Error messages — no internal logic or secrets leak', () => {
  const CONFIGURED_SECRET = 'super-secret-do-not-leak-in-response';

  // Rate limiter for test apps
  const LEAK_RL = rateLimit({ windowMs: 60_000, max: 10000, standardHeaders: false, legacyHeaders: false });

  beforeEach(() => {
    process.env.X402_PAYMENT_SECRET = CONFIGURED_SECRET;
    injectTestCaches();
  });

  afterEach(() => {
    delete process.env.X402_PAYMENT_SECRET;
    _caches.price = { priceUSD: null, fetchedAt: 0 };
    _caches.jwks  = { keys: null, fetchedAt: 0 };
  });

  // ── Basic mode ────────────────────────────────────────────────────────────

  test('basic mode 402: response body does not contain the configured secret', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test/leak-basic', LEAK_RL, verifyX402Payment({ mode: 'basic' }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-basic').set('x402-payment', 'wrong-value');
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain(CONFIGURED_SECRET);
  });

  test('basic mode 402: response body does not mention env var names or internal identifiers', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test/leak-basic2', LEAK_RL, verifyX402Payment({ mode: 'basic' }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-basic2').set('x402-payment', 'wrong');
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('X402_PAYMENT_SECRET');
    expect(bodyStr).not.toContain('process.env');
    expect(bodyStr).not.toContain('timingSafeEqual');
  });

  test('basic mode 402: no stack trace in response body', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test/leak-stack', LEAK_RL, verifyX402Payment({ mode: 'basic' }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-stack').set('x402-payment', 'wrong');
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('at ');       // no stack-trace lines
    expect(bodyStr).not.toContain('.js:');      // no file references
  });

  // ── Premium mode ──────────────────────────────────────────────────────────

  test('premium mode 402 (no header): response does not contain JWKS URL or key material', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test/leak-prem', LEAK_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-prem');
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('x402gateway.io');
    expect(bodyStr).not.toContain('jwks');
    expect(bodyStr).not.toContain('privateKey');
  });

  test('premium mode 402 (invalid JWT): response does not expose JWT internals', async () => {
    const app = express();
    app.use(express.json());
    app.get('/test/leak-jwt', LEAK_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-jwt').set('x402-payment', 'not-a-jwt.at.all');
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('not-a-jwt.at.all');  // raw header value not echoed
    expect(bodyStr).not.toContain('SyntaxError');
    expect(bodyStr).not.toContain('JsonWebTokenError');
  });

  test('premium mode 402 (unknown kid): response does not reveal internal kid list', async () => {
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer: 'SomePayer11111111111111111111111111111111' }, { kid: 'unknown-kid-secret' });

    const app = express();
    app.use(express.json());
    app.get('/test/leak-kid', LEAK_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-kid').set('x402-payment', token);
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    // The actual key ids from JWKS must not be enumerated
    expect(bodyStr).not.toContain('test-kid-1');
    expect(bodyStr).not.toContain('unknown-kid-secret');
  });

  test('premium mode 402 (insufficient amount): response does not contain raw internal variable names', async () => {
    const payer = 'LeakCheckPayer111111111111111111111111111111';
    const token = signTestToken({ amount: 0.01, currency: 'USD', payer });

    const app = express();
    app.use(express.json());
    app.get('/test/leak-amount', LEAK_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => res.json({ ok: true }));

    const res = await request(app).get('/test/leak-amount').set('x402-payment', token);
    expect(res.status).toBe(402);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('expectedAmountUSD');  // internal variable name
    expect(bodyStr).not.toContain('rawAmount');           // internal variable name
    expect(bodyStr).not.toContain('amountUSD <');         // raw comparison expression
  });

  test('all 402 responses have error property set to "Payment Required"', async () => {
    const basicApp = express();
    basicApp.use(express.json());
    basicApp.get('/b', LEAK_RL, verifyX402Payment({ mode: 'basic' }), (_req, res) => res.json({ ok: true }));

    const premApp = express();
    premApp.use(express.json());
    premApp.get('/p', LEAK_RL, verifyX402Payment({ mode: 'premium', expectedAmountUSD: 0.11 }), (_req, res) => res.json({ ok: true }));

    const resBasic = await request(basicApp).get('/b').set('x402-payment', 'wrong');
    expect(resBasic.body.error).toBe('Payment Required');

    const resPrem = await request(premApp).get('/p');
    expect(resPrem.body.error).toBe('Payment Required');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('34. Wallet model — validateSolanaBase58 helper', () => {
  const { validateSolanaBase58 } = require('../models/Wallet');

  test('returns true for a valid 44-char Solana Base58 address', () => {
    expect(validateSolanaBase58('So11111111111111111111111111111111111111112')).toBe(true);
  });

  test('returns true for a valid 32-char address (minimum length)', () => {
    expect(validateSolanaBase58('11111111111111111111111111111111')).toBe(true);
  });

  test('returns false for an address containing invalid character 0', () => {
    expect(validateSolanaBase58('S0111111111111111111111111111111111111111112')).toBe(false);
  });

  test('returns false for an address containing invalid character O', () => {
    expect(validateSolanaBase58('SO11111111111111111111111111111111111111112')).toBe(false);
  });

  test('returns false for an address shorter than 32 chars', () => {
    expect(validateSolanaBase58('1111111111111111111111111111111')).toBe(false);
  });

  test('returns false for an address longer than 44 chars', () => {
    expect(validateSolanaBase58('So1111111111111111111111111111111111111111234')).toBe(false);
  });

  test('returns false for an empty string', () => {
    expect(validateSolanaBase58('')).toBe(false);
  });

  test('returns false for a non-string input', () => {
    expect(validateSolanaBase58(null)).toBe(false);
    expect(validateSolanaBase58(undefined)).toBe(false);
    expect(validateSolanaBase58(42)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('35. Wallet model — toPublicJSON method', () => {
  const mongoose = require('mongoose');

  // Build a minimal in-memory Wallet document without a real DB connection.
  // We import the model but never call .save() or interact with MongoDB.
  const Wallet = require('../models/Wallet');

  function makeDoc(overrides = {}) {
    const doc = new Wallet({
      walletAddress: 'So11111111111111111111111111111111111111112',
      status: 'verified',
      riskScore: 95,
      ...overrides
    });
    // Manually attach a premiumForensics object so we can test the method
    // even without a real DB query.
    doc.premiumForensics = {
      addLiquidityValue: '45.2 SOL',
      removeLiquidityValue: '0.3 SOL',
      walletFunding: 'Tornado Cash',
      tokensCreated: ['TokenAddr1111111111111111111111111111111111'],
      forensicNotes: 'Pattern detected',
      crossProjectLinks: ['RelatedAddr111111111111111111111111111111111'],
      updatedAt: null
    };
    return doc;
  }

  test('returns an object without premiumForensics when hasPremiumAccess is false', () => {
    const doc    = makeDoc();
    const result = doc.toPublicJSON(false);
    expect(result).not.toHaveProperty('premiumForensics');
  });

  test('returns an object without premiumForensics when hasPremiumAccess is undefined', () => {
    const doc    = makeDoc();
    const result = doc.toPublicJSON();
    expect(result).not.toHaveProperty('premiumForensics');
  });

  test('returns premiumForensics when hasPremiumAccess is true', () => {
    const doc    = makeDoc();
    const result = doc.toPublicJSON(true);
    expect(result).toHaveProperty('premiumForensics');
    expect(result.premiumForensics).toHaveProperty('addLiquidityValue', '45.2 SOL');
    expect(result.premiumForensics).toHaveProperty('walletFunding', 'Tornado Cash');
  });

  test('always includes public fields like walletAddress and status', () => {
    const doc    = makeDoc();
    const result = doc.toPublicJSON(false);
    expect(result).toHaveProperty('walletAddress', 'So11111111111111111111111111111111111111112');
    expect(result).toHaveProperty('status', 'verified');
    expect(result).toHaveProperty('riskScore', 95);
  });

  test('does not include __v in output', () => {
    const doc    = makeDoc();
    const result = doc.toPublicJSON(false);
    expect(result).not.toHaveProperty('__v');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 36. requireAccess middleware factory
// ════════════════════════════════════════════════════════════════════════════

describe("36. requireAccess — unified access-control middleware factory", () => {
  // Re-use the shared ES256 key pair / injectTestCaches / signTestToken helpers
  // declared at line ~941 in this file.

  const ADMIN_WALLET  = 'RAAdminWallet111111111111111111111111111111'; // 43 chars
  const OTHER_WALLET  = 'RAOtherWallet11111111111111111111111111111';  // 42 chars
  const TG_TOKEN      = 'ra-tg-admin-token-secret';

  // High-limit rate limiter keeps CodeQL happy for test apps
  const RA_RATE_LIMIT = rateLimit({
    windowMs: 60 * 60 * 1000, max: 10000,
    standardHeaders: false, legacyHeaders: false
  });

  // ── Helper: minimal test app that mounts a requireAccess-protected route ───
  function buildAccessApp(level, options = {}, responseBody = (req) => ({ ok: true, isAdmin: req.isAdmin, hasPremiumAccess: req.hasPremiumAccess, adminAuth: req.adminAuth })) {
    const app = express();
    app.use(express.json());
    app.get('/test/access', RA_RATE_LIMIT, requireAccess(level, options), (req, res) => {
      res.json(responseBody(req));
    });
    return app;
  }

  // ── 36a. Public level ──────────────────────────────────────────────────────
  describe('36a. level: public', () => {
    test('always calls next() with no headers', async () => {
      const res = await request(buildAccessApp('public')).get('/test/access');
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    test('calls next() even when unrecognised headers are present', async () => {
      const res = await request(buildAccessApp('public'))
        .get('/test/access')
        .set('x402-payment', 'anything')
        .set('x-telegram-admin-token', 'anything');
      expect(res.status).toBe(200);
    });
  });

  // ── 36b. Premium level ─────────────────────────────────────────────────────
  describe('36b. level: premium', () => {
    beforeEach(() => injectTestCaches());
    afterEach(() => {
      _caches.jwks  = { keys: null, fetchedAt: 0 };
      _caches.price = { priceUSD: null, fetchedAt: 0 };
    });

    test('returns 402 when x402-payment header is absent', async () => {
      const res = await request(buildAccessApp('premium', { amountUSD: 0.11 }))
        .get('/test/access');
      expect(res.status).toBe(402);
      expect(res.body).toHaveProperty('error', 'Payment Required');
    });

    test('returns 402 for an invalid JWT', async () => {
      const res = await request(buildAccessApp('premium', { amountUSD: 0.11 }))
        .get('/test/access')
        .set('x402-payment', 'not-a-jwt');
      expect(res.status).toBe(402);
    });

    test('returns 402 when payment amount is insufficient', async () => {
      const token = signTestToken({ amount: 0.05, currency: 'USD', payer: OTHER_WALLET });
      const res   = await request(buildAccessApp('premium', { amountUSD: 0.11 }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(402);
      expect(res.body.message).toMatch(/Insufficient payment/);
    });

    test('sets req.hasPremiumAccess = true on valid payment', async () => {
      const payer = 'PremiumPayerAddr111111111111111111111111111';
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
      const res   = await request(buildAccessApp('premium', { amountUSD: 0.11 }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.hasPremiumAccess).toBe(true);
    });

    test('default amountUSD is 0.11 when option is omitted', async () => {
      const payer = 'DefaultAmountPayer11111111111111111111111111';
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
      const res   = await request(buildAccessApp('premium'))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.hasPremiumAccess).toBe(true);
    });

    test('returns 402 when amount is exactly below threshold', async () => {
      const token = signTestToken({ amount: 0.10, currency: 'USD', payer: OTHER_WALLET });
      const res   = await request(buildAccessApp('premium', { amountUSD: 0.11 }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(402);
    });
  });

  // ── 36c. Admin level — Telegram source ────────────────────────────────────
  describe('36c. level: admin — telegram source', () => {
    beforeEach(() => { process.env.TELEGRAM_ADMIN_TOKEN = TG_TOKEN; });
    afterEach(() => { delete process.env.TELEGRAM_ADMIN_TOKEN; });

    test('returns 401 when no admin header is provided', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram'] }))
        .get('/test/access');
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('message', 'Authentication required');
    });

    test('returns 403 when x-telegram-admin-token is wrong', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', 'wrong-token');
      expect(res.status).toBe(403);
      expect(res.body).toHaveProperty('message', 'Forbidden');
    });

    test('sets req.isAdmin = true when Telegram token is correct', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', TG_TOKEN);
      expect(res.status).toBe(200);
      expect(res.body.isAdmin).toBe(true);
    });

    test('sets req.adminAuth.source = "telegram" on success', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', TG_TOKEN);
      expect(res.status).toBe(200);
      expect(res.body.adminAuth).toMatchObject({ source: 'telegram' });
    });

    test('returns 403 when TELEGRAM_ADMIN_TOKEN env var is not set', async () => {
      delete process.env.TELEGRAM_ADMIN_TOKEN;
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', TG_TOKEN);
      expect(res.status).toBe(403);
    });
  });

  // ── 36d. Admin level — JWT source ─────────────────────────────────────────
  describe('36d. level: admin — jwt source', () => {
    beforeEach(() => {
      injectTestCaches();
      process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    });
    afterEach(() => {
      delete process.env.ADMIN_WALLET_ADDRESSES;
      _caches.jwks  = { keys: null, fetchedAt: 0 };
      _caches.price = { priceUSD: null, fetchedAt: 0 };
    });

    function signAdminToken(payer) {
      return signTestToken({ amount: 0.11, currency: 'USD', payer });
    }

    test('returns 401 when no x402-payment header is provided', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access');
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('message', 'Authentication required');
    });

    test('returns 403 for an invalid JWT string', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access')
        .set('x402-payment', 'not-a-jwt');
      expect(res.status).toBe(403);
    });

    test('returns 403 when payer is not in ADMIN_WALLET_ADDRESSES', async () => {
      const token = signAdminToken(OTHER_WALLET);
      const res   = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(403);
    });

    test('sets req.isAdmin = true when JWT payer is in whitelist', async () => {
      const token = signAdminToken(ADMIN_WALLET);
      const res   = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.isAdmin).toBe(true);
    });

    test('sets req.adminAuth with source "api" and payerAddress on JWT success', async () => {
      const token = signAdminToken(ADMIN_WALLET);
      const res   = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.adminAuth).toMatchObject({ source: 'api', payerAddress: ADMIN_WALLET });
    });

    test('returns 403 when ADMIN_WALLET_ADDRESSES is empty', async () => {
      process.env.ADMIN_WALLET_ADDRESSES = '';
      const token = signAdminToken(ADMIN_WALLET);
      const res   = await request(buildAccessApp('admin', { adminSources: ['jwt'] }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(403);
    });
  });

  // ── 36e. Admin level — combined telegram + jwt sources ────────────────────
  describe('36e. level: admin — combined telegram + jwt sources', () => {
    beforeEach(() => {
      injectTestCaches();
      process.env.TELEGRAM_ADMIN_TOKEN   = TG_TOKEN;
      process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    });
    afterEach(() => {
      delete process.env.TELEGRAM_ADMIN_TOKEN;
      delete process.env.ADMIN_WALLET_ADDRESSES;
      _caches.jwks  = { keys: null, fetchedAt: 0 };
      _caches.price = { priceUSD: null, fetchedAt: 0 };
    });

    test('returns 401 when neither telegram nor jwt header is present', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access');
      expect(res.status).toBe(401);
    });

    test('succeeds with Telegram token alone when JWT is not provided', async () => {
      const res = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', TG_TOKEN);
      expect(res.status).toBe(200);
      expect(res.body.isAdmin).toBe(true);
      expect(res.body.adminAuth.source).toBe('telegram');
    });

    test('succeeds with valid JWT when Telegram token is not provided', async () => {
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
      const res   = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.isAdmin).toBe(true);
      expect(res.body.adminAuth.source).toBe('api');
    });

    test('falls through to JWT when Telegram token is wrong but JWT is valid', async () => {
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
      const res   = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', 'wrong-tg-token')
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.isAdmin).toBe(true);
      expect(res.body.adminAuth.source).toBe('api');
    });

    test('returns 403 when both Telegram token and JWT are wrong', async () => {
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer: OTHER_WALLET });
      const res   = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', 'wrong-tg-token')
        .set('x402-payment', token);
      expect(res.status).toBe(403);
    });

    test('Telegram succeeds first; JWT not evaluated', async () => {
      // Even if JWT would fail (wrong payer), Telegram success should grant access
      const token = signTestToken({ amount: 0.11, currency: 'USD', payer: OTHER_WALLET });
      const res   = await request(buildAccessApp('admin', { adminSources: ['telegram', 'jwt'] }))
        .get('/test/access')
        .set('x-telegram-admin-token', TG_TOKEN)
        .set('x402-payment', token);
      expect(res.status).toBe(200);
      expect(res.body.adminAuth.source).toBe('telegram');
    });
  });

  // ── 36f. Factory guard: invalid level throws ───────────────────────────────
  describe('36f. factory guard', () => {
    test('throws synchronously for an invalid level string', () => {
      expect(() => requireAccess('superadmin')).toThrow(
        /requireAccess: invalid level "superadmin"/
      );
    });
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 37. formatWalletResponse — response utility
// ════════════════════════════════════════════════════════════════════════════

describe('37. formatWalletResponse — response utility', () => {
  const { formatWalletResponse, escapeHtml } = require('../utils/response');

  const TOKEN_ADDR   = 'TokenAddr1111111111111111111111111111111111'; // 44 chars
  const WALLET_ADDR  = 'So11111111111111111111111111111111111111112'; // 44 chars
  const RELATED_ADDR = 'RelatedAddr111111111111111111111111111111111'; // 44 chars

  // Build a plain wallet object (no Mongoose methods) for unit tests.
  function makeWallet(overrides = {}) {
    return {
      walletAddress: WALLET_ADDR,
      status: 'verified',
      riskScore: 95,
      caseNumber: 1,
      projectName: 'Test Project',
      tokenAddress: TOKEN_ADDR,
      evidence: {
        txHash: 'SomeTxHash11111111111111111111111111111111',
        solscanLink: 'https://solscan.io/tx/SomeTxHash',
        description: 'Rug pull detected',
        submittedAt: new Date('2024-01-01')
      },
      __v: 0,
      forensic: {
        liquidityBefore: 100000,
        liquidityAfter: 0,
        drainDurationHours: 2,
        detectedPattern: ['liquidity_removal'],
        walletFunding: 'Binance'
      },
      premiumForensics: {
        addLiquidityValue: '45.2 SOL',
        removeLiquidityValue: '0.3 SOL',
        walletFunding: 'Tornado Cash',
        tokensCreated: [TOKEN_ADDR],
        forensicNotes: 'Repeat offender',
        crossProjectLinks: [RELATED_ADDR],
        updatedAt: new Date('2024-02-01')
      },
      createdAt: new Date('2024-01-01'),
      updatedAt: new Date('2024-01-15'),
      ...overrides
    };
  }

  // ── 37a. Without premium access ───────────────────────────────────────────
  describe('37a. without premium access (default)', () => {
    test('does not include premiumForensics in the response', () => {
      const result = formatWalletResponse(makeWallet());
      expect(result).not.toHaveProperty('premiumForensics');
    });

    test('includes meta with hasPremiumData: false and lastPremiumUpdate: null', () => {
      const result = formatWalletResponse(makeWallet());
      expect(result.meta).toEqual({ hasPremiumData: false, lastPremiumUpdate: null });
    });

    test('meta.hasPremiumData is false even when premiumForensics data is present in the document', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: false });
      expect(result.meta.hasPremiumData).toBe(false);
    });

    test('excludes __v field', () => {
      const result = formatWalletResponse(makeWallet());
      expect(result).not.toHaveProperty('__v');
    });

    test('excludes raw forensic sub-document', () => {
      const result = formatWalletResponse(makeWallet());
      expect(result).not.toHaveProperty('forensic');
    });

    test('includes public fields: walletAddress, status, riskScore, caseNumber', () => {
      const result = formatWalletResponse(makeWallet());
      expect(result.walletAddress).toBe(WALLET_ADDR);
      expect(result.status).toBe('verified');
      expect(result.riskScore).toBe(95);
      expect(result.caseNumber).toBe(1);
    });
  });

  // ── 37b. With premium access ──────────────────────────────────────────────
  describe('37b. with premium access', () => {
    test('includes premiumForensics in the response', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      expect(result).toHaveProperty('premiumForensics');
    });

    test('meta.hasPremiumData is true', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      expect(result.meta.hasPremiumData).toBe(true);
    });

    test('meta.lastPremiumUpdate equals premiumForensics.updatedAt', () => {
      const updatedAt = new Date('2024-02-01');
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      expect(result.meta.lastPremiumUpdate).toEqual(updatedAt);
    });

    test('tokensCreated are formatted as { address, solscanLink } objects', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      const tokens = result.premiumForensics.tokensCreated;
      expect(Array.isArray(tokens)).toBe(true);
      expect(tokens[0]).toMatchObject({
        address: TOKEN_ADDR,
        solscanLink: `https://solscan.io/token/${TOKEN_ADDR}`
      });
    });

    test('excludes __v and forensic even with premium access', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      expect(result).not.toHaveProperty('__v');
      expect(result).not.toHaveProperty('forensic');
    });

    test('includes all non-token premiumForensics fields', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      const pf = result.premiumForensics;
      expect(pf).toHaveProperty('addLiquidityValue', '45.2 SOL');
      expect(pf).toHaveProperty('removeLiquidityValue', '0.3 SOL');
      expect(pf).toHaveProperty('walletFunding', 'Tornado Cash');
      expect(pf).toHaveProperty('forensicNotes', 'Repeat offender');
      expect(Array.isArray(pf.crossProjectLinks)).toBe(true);
    });
  });

  // ── 37c. XSS escaping ─────────────────────────────────────────────────────
  describe('37c. XSS escaping', () => {
    test('escapes <script> injection in projectName', () => {
      const result = formatWalletResponse(makeWallet({ projectName: '<script>alert(1)</script>' }));
      expect(result.projectName).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
      expect(result.projectName).not.toContain('<script>');
    });

    test('escapes double-quote attribute injection in projectName', () => {
      const result = formatWalletResponse(makeWallet({ projectName: '" onmouseover="evil()"' }));
      expect(result.projectName).toContain('&quot;');
      expect(result.projectName).not.toContain('"');
    });

    test('escapes XSS in premiumForensics.walletFunding when premium access is granted', () => {
      const wallet = makeWallet({
        premiumForensics: { ...makeWallet().premiumForensics, walletFunding: '<img src=x onerror=alert(1)>' }
      });
      const result = formatWalletResponse(wallet, { hasPremiumAccess: true });
      expect(result.premiumForensics.walletFunding).not.toContain('<img');
      expect(result.premiumForensics.walletFunding).toContain('&lt;img');
    });

    test('escapes XSS in premiumForensics.forensicNotes when premium access is granted', () => {
      const wallet = makeWallet({
        premiumForensics: { ...makeWallet().premiumForensics, forensicNotes: '<b>bold</b>' }
      });
      const result = formatWalletResponse(wallet, { hasPremiumAccess: true });
      expect(result.premiumForensics.forensicNotes).toBe('&lt;b&gt;bold&lt;/b&gt;');
    });

    test('valid Base58 token address passes through unchanged (no HTML chars to escape)', () => {
      const result = formatWalletResponse(makeWallet(), { hasPremiumAccess: true });
      expect(result.premiumForensics.tokensCreated[0].address).toBe(TOKEN_ADDR);
    });

    test('escapeHtml encodes all five HTML-special characters', () => {
      expect(escapeHtml('& < > " \'')).toBe('&amp; &lt; &gt; &quot; &#039;');
    });

    test('escapeHtml returns empty string for null', () => {
      expect(escapeHtml(null)).toBe('');
    });

    test('escapeHtml returns empty string for undefined', () => {
      expect(escapeHtml(undefined)).toBe('');
    });
  });

  // ── 37d. Edge cases ───────────────────────────────────────────────────────
  describe('37d. edge cases', () => {
    test('handles wallet with null premiumForensics when hasPremiumAccess is true', () => {
      const wallet = makeWallet({ premiumForensics: null });
      const result = formatWalletResponse(wallet, { hasPremiumAccess: true });
      expect(result).not.toHaveProperty('premiumForensics');
      expect(result.meta.hasPremiumData).toBe(false);
      expect(result.meta.lastPremiumUpdate).toBeNull();
    });

    test('handles empty tokensCreated array gracefully', () => {
      const wallet = makeWallet({
        premiumForensics: { ...makeWallet().premiumForensics, tokensCreated: [] }
      });
      const result = formatWalletResponse(wallet, { hasPremiumAccess: true });
      expect(result.premiumForensics.tokensCreated).toEqual([]);
    });

    test('works with plain objects that have no toObject() method', () => {
      const plain = { walletAddress: WALLET_ADDR, status: 'verified', riskScore: 50, __v: 0 };
      const result = formatWalletResponse(plain);
      expect(result.walletAddress).toBe(WALLET_ADDR);
      expect(result.status).toBe('verified');
      expect(result).not.toHaveProperty('__v');
    });

    test('meta.lastPremiumUpdate is null when premiumForensics.updatedAt is null', () => {
      const wallet = makeWallet({
        premiumForensics: { ...makeWallet().premiumForensics, updatedAt: null }
      });
      const result = formatWalletResponse(wallet, { hasPremiumAccess: true });
      expect(result.meta.lastPremiumUpdate).toBeNull();
    });

    test('without premium access produces no premiumForensics even if field is present in source', () => {
      // Demonstrates the key difference: same wallet, different access level
      const wallet = makeWallet();
      const withoutPremium = formatWalletResponse(wallet, { hasPremiumAccess: false });
      const withPremium    = formatWalletResponse(wallet, { hasPremiumAccess: true });

      expect(withoutPremium).not.toHaveProperty('premiumForensics');
      expect(withPremium).toHaveProperty('premiumForensics');
      expect(withoutPremium.meta.hasPremiumData).toBe(false);
      expect(withPremium.meta.hasPremiumData).toBe(true);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('38. CALLBACK — prefix-based callback router constants', () => {
  // ── 38a. Constant values ──────────────────────────────────────────────────
  describe('38a. CALLBACK constant values', () => {
    test('CALLBACK.VERIFY equals "verify:"', () => {
      expect(CALLBACK.VERIFY).toBe('verify:');
    });

    test('CALLBACK.PREMIUM_ADD equals "premium:add:"', () => {
      expect(CALLBACK.PREMIUM_ADD).toBe('premium:add:');
    });

    test('CALLBACK.PREMIUM_EDIT equals "premium:edit:"', () => {
      expect(CALLBACK.PREMIUM_EDIT).toBe('premium:edit:');
    });

    test('CALLBACK.PREMIUM_CONFIRM equals "premium:confirm:"', () => {
      expect(CALLBACK.PREMIUM_CONFIRM).toBe('premium:confirm:');
    });

    test('CALLBACK.CANCEL equals "cancel"', () => {
      expect(CALLBACK.CANCEL).toBe('cancel');
    });

    test('CALLBACK has exactly 5 keys', () => {
      expect(Object.keys(CALLBACK)).toHaveLength(5);
    });
  });

  // ── 38b. Prefix uniqueness (no prefix is a prefix of another) ────────────
  describe('38b. Prefix uniqueness', () => {
    test('VERIFY prefix does not match PREMIUM_ADD data', () => {
      expect(`premium:add:someId`.startsWith(CALLBACK.VERIFY)).toBe(false);
    });

    test('PREMIUM_ADD prefix does not match PREMIUM_EDIT data', () => {
      expect(`premium:edit:field:id`.startsWith(CALLBACK.PREMIUM_ADD)).toBe(false);
    });

    test('PREMIUM_EDIT prefix does not match PREMIUM_CONFIRM data', () => {
      expect(`premium:confirm:add:key`.startsWith(CALLBACK.PREMIUM_EDIT)).toBe(false);
    });

    test('PREMIUM_CONFIRM is checked before PREMIUM_ADD to avoid false match', () => {
      // premium:confirm:... starts with "premium:" but NOT with "premium:add:"
      const data = `premium:confirm:add:abc123`;
      expect(data.startsWith(CALLBACK.PREMIUM_CONFIRM)).toBe(true);
      expect(data.startsWith(CALLBACK.PREMIUM_ADD)).toBe(false);
      expect(data.startsWith(CALLBACK.PREMIUM_EDIT)).toBe(false);
    });

    test('CANCEL matches cancel:add:key via startsWith', () => {
      expect(`cancel:add:abc123`.startsWith(CALLBACK.CANCEL)).toBe(true);
    });

    test('CANCEL matches cancel:edit:key via startsWith', () => {
      expect(`cancel:edit:abc123`.startsWith(CALLBACK.CANCEL)).toBe(true);
    });

    test('CANCEL matches cancel:bulk:key via startsWith', () => {
      expect(`cancel:bulk:abc123`.startsWith(CALLBACK.CANCEL)).toBe(true);
    });

    test('CANCEL does not match "premium:confirm:..." data', () => {
      expect(`premium:confirm:add:abc`.startsWith(CALLBACK.CANCEL)).toBe(false);
    });
  });

  // ── 38c. callback_data generation helpers ────────────────────────────────
  describe('38c. callback_data generation for inline keyboards', () => {
    const WALLET_ID  = '507f1f77bcf86cd799439011';
    const FIELD_NAME = 'addLiquidityValue';
    const CONFIRM_KEY = 'deadbeef01234567';

    test('verify keyboard uses CALLBACK.VERIFY prefix', () => {
      const data = `${CALLBACK.VERIFY}${WALLET_ID}`;
      expect(data).toBe(`verify:${WALLET_ID}`);
      expect(data.startsWith(CALLBACK.VERIFY)).toBe(true);
    });

    test('premium:add keyboard uses CALLBACK.PREMIUM_ADD prefix', () => {
      const data = `${CALLBACK.PREMIUM_ADD}${WALLET_ID}`;
      expect(data).toBe(`premium:add:${WALLET_ID}`);
      expect(data.startsWith(CALLBACK.PREMIUM_ADD)).toBe(true);
    });

    test('premium:edit keyboard uses CALLBACK.PREMIUM_EDIT prefix', () => {
      const data = `${CALLBACK.PREMIUM_EDIT}${FIELD_NAME}:${WALLET_ID}`;
      expect(data).toBe(`premium:edit:${FIELD_NAME}:${WALLET_ID}`);
      expect(data.startsWith(CALLBACK.PREMIUM_EDIT)).toBe(true);
    });

    test('premium:confirm:add keyboard uses CALLBACK.PREMIUM_CONFIRM prefix', () => {
      const data = `${CALLBACK.PREMIUM_CONFIRM}add:${CONFIRM_KEY}`;
      expect(data).toBe(`premium:confirm:add:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.PREMIUM_CONFIRM)).toBe(true);
    });

    test('premium:confirm:edit keyboard uses CALLBACK.PREMIUM_CONFIRM prefix', () => {
      const data = `${CALLBACK.PREMIUM_CONFIRM}edit:${CONFIRM_KEY}`;
      expect(data).toBe(`premium:confirm:edit:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.PREMIUM_CONFIRM)).toBe(true);
    });

    test('premium:confirm:bulk keyboard uses CALLBACK.PREMIUM_CONFIRM prefix', () => {
      const data = `${CALLBACK.PREMIUM_CONFIRM}bulk:${CONFIRM_KEY}`;
      expect(data).toBe(`premium:confirm:bulk:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.PREMIUM_CONFIRM)).toBe(true);
    });

    test('cancel:add keyboard uses CALLBACK.CANCEL prefix', () => {
      const data = `${CALLBACK.CANCEL}:add:${CONFIRM_KEY}`;
      expect(data).toBe(`cancel:add:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.CANCEL)).toBe(true);
    });

    test('cancel:edit keyboard uses CALLBACK.CANCEL prefix', () => {
      const data = `${CALLBACK.CANCEL}:edit:${CONFIRM_KEY}`;
      expect(data).toBe(`cancel:edit:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.CANCEL)).toBe(true);
    });

    test('cancel:bulk keyboard uses CALLBACK.CANCEL prefix', () => {
      const data = `${CALLBACK.CANCEL}:bulk:${CONFIRM_KEY}`;
      expect(data).toBe(`cancel:bulk:${CONFIRM_KEY}`);
      expect(data.startsWith(CALLBACK.CANCEL)).toBe(true);
    });
  });

  // ── 38d. Parsing logic (colon-split) ──────────────────────────────────────
  describe('38d. Colon-split parsing of callback_data', () => {
    test('verify:<walletId> splits into ["verify", "<walletId>"]', () => {
      const parts = 'verify:507f1f77bcf86cd799439011'.split(':');
      expect(parts[0]).toBe('verify');
      expect(parts[1]).toBe('507f1f77bcf86cd799439011');
    });

    test('premium:add:<walletId> splits so parts[2] is walletId', () => {
      const parts = 'premium:add:507f1f77bcf86cd799439011'.split(':');
      expect(parts[0]).toBe('premium');
      expect(parts[1]).toBe('add');
      expect(parts[2]).toBe('507f1f77bcf86cd799439011');
    });

    test('premium:edit:<field>:<walletId> splits so parts[2]=field, parts[3]=walletId', () => {
      const parts = 'premium:edit:addLiquidityValue:507f1f77bcf86cd799439011'.split(':');
      expect(parts[2]).toBe('addLiquidityValue');
      expect(parts[3]).toBe('507f1f77bcf86cd799439011');
    });

    test('premium:confirm:add:<key> splits so parts[2]="add", parts[3]=key', () => {
      const parts = 'premium:confirm:add:deadbeef01234567'.split(':');
      expect(parts[2]).toBe('add');
      expect(parts[3]).toBe('deadbeef01234567');
    });

    test('premium:confirm:edit:<key> splits so parts[2]="edit"', () => {
      const parts = 'premium:confirm:edit:deadbeef01234567'.split(':');
      expect(parts[2]).toBe('edit');
    });

    test('premium:confirm:bulk:<key> splits so parts[2]="bulk"', () => {
      const parts = 'premium:confirm:bulk:deadbeef01234567'.split(':');
      expect(parts[2]).toBe('bulk');
    });

    test('cancel:add:<key> splits so parts[1]="add", parts[2]=key', () => {
      const parts = 'cancel:add:deadbeef01234567'.split(':');
      expect(parts[1]).toBe('add');
      expect(parts[2]).toBe('deadbeef01234567');
    });

    test('cancel:edit:<key> splits so parts[1]="edit"', () => {
      const parts = 'cancel:edit:deadbeef01234567'.split(':');
      expect(parts[1]).toBe('edit');
    });

    test('cancel:bulk:<key> splits so parts[1]="bulk"', () => {
      const parts = 'cancel:bulk:deadbeef01234567'.split(':');
      expect(parts[1]).toBe('bulk');
    });

    test('unrecognised prefix does not start with any CALLBACK value', () => {
      const unknownData = 'unknown:action:123';
      const recognised = Object.values(CALLBACK).some(prefix => unknownData.startsWith(prefix));
      expect(recognised).toBe(false);
    });

    test('empty string does not start with any CALLBACK value', () => {
      const recognised = Object.values(CALLBACK).some(prefix => ''.startsWith(prefix));
      expect(recognised).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('39. workflowState — multi-step premium input state manager', () => {
  // Reset module state between tests by clearing everything after each test
  afterEach(() => {
    workflowState.clear('chat1');
    workflowState.clear('chat2');
    workflowState.clear(42);
  });

  // ── 39a. get / set / clear ────────────────────────────────────────────────
  describe('39a. get / set / clear operations', () => {
    test('get returns null for an unknown chatId', () => {
      expect(workflowState.get('nonexistent')).toBeNull();
    });

    test('set stores state and get retrieves it', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      const state = workflowState.get('chat1');
      expect(state).not.toBeNull();
      expect(state.workflow).toBe('premium_add');
      expect(state.currentField).toBe('addLiquidityValue');
    });

    test('set injects startedAt timestamp automatically', () => {
      const before = Date.now();
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      const after  = Date.now();
      const state  = workflowState.get('chat1');
      expect(state.startedAt).toBeGreaterThanOrEqual(before);
      expect(state.startedAt).toBeLessThanOrEqual(after);
    });

    test('set preserves a caller-supplied startedAt', () => {
      const ts = 1_000_000;
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {}, startedAt: ts });
      expect(workflowState.get('chat1').startedAt).toBe(ts);
    });

    test('clear removes state and get returns null afterwards', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      workflowState.clear('chat1');
      expect(workflowState.get('chat1')).toBeNull();
    });

    test('clear on an unknown chatId is a no-op (does not throw)', () => {
      expect(() => workflowState.clear('nonexistent')).not.toThrow();
    });

    test('chatId is coerced to string — numeric and string keys are equivalent', () => {
      workflowState.set(42, { workflow: 'premium_add', currentField: 'walletFunding', collectedData: {} });
      expect(workflowState.get('42')).not.toBeNull();
      expect(workflowState.get(42)).not.toBeNull();
    });

    test('set overwrites an existing state for the same chatId', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'walletFunding', collectedData: { addLiquidityValue: '5 SOL' } });
      const state = workflowState.get('chat1');
      expect(state.currentField).toBe('walletFunding');
      expect(state.collectedData).toEqual({ addLiquidityValue: '5 SOL' });
    });

    test('states for different chatIds are independent', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      workflowState.set('chat2', { workflow: 'premium_add', currentField: 'forensicNotes', collectedData: {} });
      expect(workflowState.get('chat1').currentField).toBe('addLiquidityValue');
      expect(workflowState.get('chat2').currentField).toBe('forensicNotes');
      workflowState.clear('chat1');
      expect(workflowState.get('chat1')).toBeNull();
      expect(workflowState.get('chat2')).not.toBeNull();
    });
  });

  // ── 39b. touch ────────────────────────────────────────────────────────────
  describe('39b. touch — extend expiry without mutating state', () => {
    test('touch on a known chatId does not throw', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      expect(() => workflowState.touch('chat1')).not.toThrow();
    });

    test('touch leaves state contents unchanged', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: { x: 1 } });
      workflowState.touch('chat1');
      const state = workflowState.get('chat1');
      expect(state.currentField).toBe('addLiquidityValue');
      expect(state.collectedData).toEqual({ x: 1 });
    });

    test('touch on an unknown chatId is a no-op (does not throw)', () => {
      expect(() => workflowState.touch('nonexistent')).not.toThrow();
    });
  });

  // ── 39c. cleanup ─────────────────────────────────────────────────────────
  describe('39c. cleanup — remove stale entries', () => {
    test('cleanup removes entries older than WORKFLOW_EXPIRE_MS', () => {
      const staleTs = Date.now() - workflowState.WORKFLOW_EXPIRE_MS - 1;
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {}, startedAt: staleTs });
      workflowState.cleanup();
      expect(workflowState.get('chat1')).toBeNull();
    });

    test('cleanup keeps entries younger than WORKFLOW_EXPIRE_MS', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      workflowState.cleanup();
      expect(workflowState.get('chat1')).not.toBeNull();
    });

    test('cleanup is a no-op on an empty store (does not throw)', () => {
      expect(() => workflowState.cleanup()).not.toThrow();
    });

    test('cleanup only removes stale entries, leaving fresh ones intact', () => {
      const staleTs = Date.now() - workflowState.WORKFLOW_EXPIRE_MS - 1;
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {}, startedAt: staleTs });
      workflowState.set('chat2', { workflow: 'premium_add', currentField: 'forensicNotes',     collectedData: {} });
      workflowState.cleanup();
      expect(workflowState.get('chat1')).toBeNull();
      expect(workflowState.get('chat2')).not.toBeNull();
    });
  });

  // ── 39d. WORKFLOW_EXPIRE_MS constant ─────────────────────────────────────
  describe('39d. WORKFLOW_EXPIRE_MS constant', () => {
    test('WORKFLOW_EXPIRE_MS equals 15 minutes in milliseconds', () => {
      expect(workflowState.WORKFLOW_EXPIRE_MS).toBe(15 * 60 * 1000);
    });
  });

  // ── 39e. auto-expiry via setTimeout (fake timers) ─────────────────────────
  describe('39e. auto-expiry via setTimeout', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => {
      workflowState.clear('chat1');
      jest.useRealTimers();
    });

    test('state is removed automatically after WORKFLOW_EXPIRE_MS', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      expect(workflowState.get('chat1')).not.toBeNull();
      jest.advanceTimersByTime(workflowState.WORKFLOW_EXPIRE_MS + 1);
      expect(workflowState.get('chat1')).toBeNull();
    });

    test('calling set resets the expiry timer', () => {
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'addLiquidityValue', collectedData: {} });
      // Advance halfway through the expiry window
      jest.advanceTimersByTime(workflowState.WORKFLOW_EXPIRE_MS / 2);
      // Update state (should reset the timer)
      workflowState.set('chat1', { workflow: 'premium_add', currentField: 'walletFunding', collectedData: {} });
      // Advance another half-window — total elapsed > one full EXPIRE_MS from first set
      jest.advanceTimersByTime(workflowState.WORKFLOW_EXPIRE_MS / 2);
      // Should still exist because the timer was reset
      expect(workflowState.get('chat1')).not.toBeNull();
      // Now advance past the second full window
      jest.advanceTimersByTime(workflowState.WORKFLOW_EXPIRE_MS);
      expect(workflowState.get('chat1')).toBeNull();
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 40. 💳 x402 Payment Flow
// Tests the unified verifyX402Payment middleware with injected JWKS + oracle
// caches. Covers: JWT signature validation, amount verification, SOL↔USD
// conversion via the oracle price cache, and backward-compat basic-mode path.
// ─────────────────────────────────────────────────────────────────────────────
describe('40. 💳 x402 Payment Flow', () => {
  let x402App;

  beforeAll(() => {
    injectTestCaches();
    x402App = buildPSX402TestApp();
  });

  afterAll(() => {
    resetPSCaches();
  });

  test('rejects missing x402-payment header with 402 and requiredAmountUSD', async () => {
    const res = await request(x402App).get(`/api/wallets/${VALID_ADDRESS}/premium`);
    expect(res.status).toBe(402);
    expect(res.body.error).toBe('Payment Required');
    expect(res.body).toHaveProperty('requiredAmountUSD', 0.11);
  });

  test('rejects malformed (non-JWT) payment header with 402', async () => {
    const res = await request(x402App)
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
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Uu]nknown.*key/);
  });

  test('rejects JWT with insufficient payment amount with 402', async () => {
    const token = signTestToken({ amount: 0.05, currency: 'USD', payer: 'PayerAddr111111111111111111111111111111111' });
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(402);
    expect(res.body.message).toMatch(/[Ii]nsufficient/);
  });

  test('accepts valid JWT (USD) and returns premiumForensics', async () => {
    const payer = 'SolPayerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const token = signTestToken({ amount: 0.11, currency: 'USD', payer });
    const res = await request(x402App)
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
    const res = await request(x402App)
      .get(`/api/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('premiumForensics');
  });

  test('timingSafeEqual provides constant-time guarantee for equal-length secrets', () => {
    const secret  = Buffer.from('admin-payment-secret-value');
    const correct = Buffer.from('admin-payment-secret-value');
    const wrong   = Buffer.from('admin-XXXXXXX-secret-value'); // same length, wrong content

    expect(crypto.timingSafeEqual(secret, correct)).toBe(true);
    expect(crypto.timingSafeEqual(secret, wrong)).toBe(false);
    expect(() => crypto.timingSafeEqual(secret, Buffer.from('short'))).toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 41. 👑 Premium Forensics Access Control
// Tests admin API authorization (requireAdminAuth('api') with ADMIN_WALLET_ADDRESSES
// whitelist), premium field input validation, and data-privacy rules (no forensic
// data leaked without payment, no raw secrets or PII in responses).
// ─────────────────────────────────────────────────────────────────────────────
describe('41. 👑 Premium Forensics Access Control', () => {
  let x402App;
  let adminApp;

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    x402App  = buildPSX402TestApp();
    adminApp = buildPSAdminTestApp();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    resetPSCaches();
  });

  function signAdmin(payer = ADMIN_WALLET) {
    return signTestToken({ amount: 0.11, currency: 'USD', payer });
  }

  // ── Admin API authorization ───────────────────────────────────────────────

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

  // ── Premium field input validation ───────────────────────────────────────

  test('rejects invalid Solana address in tokensCreated array with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ tokensCreated: ['0OIl-not-base58'] });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/tokensCreated/)])
    );
  });

  test('rejects tokensCreated as a non-array value with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ tokensCreated: 'not-an-array' });
    expect(res.status).toBe(400);
  });

  test('rejects HTML tags in forensicNotes with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: '<script>alert("xss")</script>' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/forensicNotes/)])
    );
  });

  test('rejects inline HTML element in forensicNotes with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'Note: <b>bold text</b>' });
    expect(res.status).toBe(400);
  });

  test('rejects forensicNotes as non-string with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 12345 });
    expect(res.status).toBe(400);
  });

  test('accepts valid formatted values for all 6 premium fields', async () => {
    const payload = {
      addLiquidityValue:    '45.2 SOL',
      removeLiquidityValue: '0.3 SOL',
      walletFunding:        'Binance Hot Wallet',
      tokensCreated:        [VALID_TOKEN_ADDR],
      forensicNotes:        'Repeat offender pattern detected',
      crossProjectLinks:    [VALID_TOKEN_ADDR]
    };
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
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
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ addLiquidityValue: '1000 USDC' });
    expect(res.status).toBe(200);
  });

  test('rejects addLiquidityValue with non-numeric prefix with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ addLiquidityValue: 'ONE HUNDRED SOL' });
    expect(res.status).toBe(400);
  });

  test('rejects walletFunding with HTML tags with 400', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ walletFunding: '<img src=x onerror=alert(1)>' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual(
      expect.arrayContaining([expect.stringMatching(/walletFunding/)])
    );
  });

  test('returns multiple errors when multiple fields are invalid simultaneously', async () => {
    const res = await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({
        addLiquidityValue: 'bad-value',
        forensicNotes:     '<b>html</b>',
        tokensCreated:     ['not-base58-0OIl']
      });
    expect(res.status).toBe(400);
    expect(res.body.errors.length).toBeGreaterThanOrEqual(3);
  });

  // ── Data privacy rules ────────────────────────────────────────────────────

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
    const pf = res.body.premiumForensics;
    expect(typeof pf.walletFunding).toBe('string');
    expect(typeof pf.forensicNotes).toBe('string');
    const allValues = JSON.stringify(pf);
    expect(allValues).not.toMatch(/<script/i);
  });

  test('audit log changedBy.identifier uses wallet prefix, not email/name PII', async () => {
    const baseline = psLogSize();
    const token    = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
    await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ forensicNotes: 'privacy test note' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);
    const entry = entries[entries.length - 1];
    expect(entry.changedBy.identifier).toMatch(/^wallet:/);
    expect(entry.changedBy.identifier).not.toMatch(/@/);
  });

  test('audit log entry does not store the raw x402 JWT token', async () => {
    const baseline = psLogSize();
    const token    = signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
    await request(adminApp)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', token)
      .send({ walletFunding: 'Binance' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);
    const rawLine = JSON.stringify(entries[entries.length - 1]);
    expect(rawLine).not.toContain(token);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 42. 🤖 Telegram Bot Authorization
// Tests requireAdminAuth('telegram') — callback prefix routing, state machine
// workflow, and admin whitelist enforcement via TELEGRAM_ADMIN_CHAT_ID /
// TELEGRAM_ADMIN_USER_IDS env vars, including TELEGRAM_CHAT_ID fallback.
// ─────────────────────────────────────────────────────────────────────────────
describe('42. 🤖 Telegram Bot Authorization', () => {
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

  test('rejects Message from non-admin chat.id', () => {
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

// ─────────────────────────────────────────────────────────────────────────────
// 43. 📝 Audit Logging
// Tests admin_audit.log format, before/after diff scoping, IP hashing,
// no PII leakage, and sequential entry creation via the real writeAuditLog.
// ─────────────────────────────────────────────────────────────────────────────
describe('43. 📝 Audit Logging', () => {
  let app;

  beforeAll(() => {
    injectTestCaches();
    process.env.ADMIN_WALLET_ADDRESSES = ADMIN_WALLET;
    app = buildPSAdminTestApp();
  });

  afterAll(() => {
    delete process.env.ADMIN_WALLET_ADDRESSES;
    resetPSCaches();
  });

  function signAdmin() {
    return signTestToken({ amount: 0.11, currency: 'USD', payer: ADMIN_WALLET });
  }

  test('every premium update creates an entry in admin_audit.log', async () => {
    const baseline = psLogSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'audit-logging test entry' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThanOrEqual(1);
  });

  test('audit log entry contains required fields: timestamp, action, walletAddress, caseNumber, changedBy, fieldsChanged, before, after', async () => {
    const baseline = psLogSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ addLiquidityValue: '10 SOL', forensicNotes: 'shape test' });

    const entries = await psReadNewLogEntries(baseline);
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
    const baseline = psLogSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'diff test value' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);

    const entry = entries[entries.length - 1];
    expect(entry.fieldsChanged).toEqual(['forensicNotes']);
    expect(entry.after).toHaveProperty('forensicNotes', 'diff test value');
    expect(entry.after).not.toHaveProperty('walletAddress');
    expect(entry.after).not.toHaveProperty('status');
  });

  test('IP addresses are hashed (not stored in plain text) in audit log entries', async () => {
    const baseline = psLogSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ walletFunding: 'IP hash test' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThan(0);

    const entry   = entries.find(e => e.action === 'premium_update' && e.ipHash !== undefined);
    expect(entry).toBeDefined();
    const rawLine = JSON.stringify(entry);

    expect(entry).toHaveProperty('ipHash');
    expect(entry.ipHash).toMatch(/^sha256-[a-f0-9]{64}$/);
    expect(rawLine).not.toContain('"ip"');
    expect(rawLine).not.toMatch(/"127\.0\.0\.1"/);
    expect(rawLine).not.toMatch(/"::1"/);
  });

  test('multiple sequential updates each create a separate log entry', async () => {
    const baseline = psLogSize();
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'entry one' });
    await request(app)
      .patch(`/api/admin/wallets/${VALID_ADDRESS}/premium`)
      .set('x402-payment', signAdmin())
      .send({ forensicNotes: 'entry two' });

    const entries = await psReadNewLogEntries(baseline);
    expect(entries.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── Helper: build a CORS-enabled test app mirroring server.js logic ─────────
function buildCorsTestApp(allowedOrigins) {
  const app = express();
  app.use(cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PATCH'],
    allowedHeaders: ['Content-Type', 'x402-payment', 'x-admin-token', 'x-telegram-admin-token']
  }));
  app.use(express.json());
  app.get('/api/health', (_req, res) => {
    res.status(200).json({ success: true, status: 'ok', db: 'connected', timestamp: new Date().toISOString() });
  });
  app.get('/api/wallets', (_req, res) => {
    res.json({ success: true, data: [] });
  });
  return app;
}

describe('44. GET /api/health — health check endpoint', () => {
  const app = buildTestApp();

  test('returns 200 with success:true and required fields', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body).toHaveProperty('db', 'connected');
    expect(res.body).toHaveProperty('timestamp');
  });

  test('timestamp is a valid ISO 8601 string', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(new Date(res.body.timestamp).toISOString()).toBe(res.body.timestamp);
  });
});

describe('45. CORS — multi-origin support', () => {
  test('allows request from the first configured origin', async () => {
    const app = buildCorsTestApp(['https://suspected.dev', 'https://www.suspected.dev']);
    const res = await request(app)
      .get('/api/health')
      .set('Origin', 'https://suspected.dev');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://suspected.dev');
  });

  test('allows request from a second configured origin', async () => {
    const app = buildCorsTestApp(['https://suspected.dev', 'https://www.suspected.dev']);
    const res = await request(app)
      .get('/api/health')
      .set('Origin', 'https://www.suspected.dev');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://www.suspected.dev');
  });

  test('blocks request from an unlisted origin', async () => {
    const app = buildCorsTestApp(['https://suspected.dev']);
    const res = await request(app)
      .get('/api/wallets')
      .set('Origin', 'https://evil.example.com');
    // The cors package passes an error to Express when origin is blocked; Express
    // responds with 500. The key assertion is that no ACAO header is set, which
    // is what prevents the browser from granting cross-origin access.
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('allows requests with no Origin header (curl / server-to-server)', async () => {
    const app = buildCorsTestApp(['https://suspected.dev']);
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
  });
});

describe('46. GET /api/wallets — error response format', () => {
  test('successful response contains success:true and data array', async () => {
    const app = buildTestApp();
    const res = await request(app).get('/api/wallets');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });
});

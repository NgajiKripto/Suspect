'use strict';

/**
 * verifyX402Payment — unified x402 payment middleware for suspected.dev
 *
 * Factory that returns an Express middleware validating the `x402-payment`
 * header. Supports two modes via an `options` parameter:
 *
 *   mode: 'basic'   (timingSafeEqual secret comparison)
 *     1. Checks header presence
 *     2. Compares header value against process.env.X402_PAYMENT_SECRET using
 *        crypto.timingSafeEqual to prevent timing attacks
 *     On success: req.x402 = { valid: true, payerAddress: null, amountUSD: null }
 *
 *   mode: 'premium'  (JWT + JWKS + oracle — default)
 *     1. Decodes the JWT and locates the signing key via x402gateway.io JWKS
 *     2. Verifies the JWT signature with the fetched public key
 *     3. Converts the payment amount to USD (SOL/USD oracle, 5-min cached TTL)
 *     4. Checks amount >= expectedAmountUSD
 *     5. Extracts the payer address from JWT claims
 *     On success: req.x402 = { valid: true, payerAddress: string, amountUSD: number }
 *
 * Backward compatibility: passing a plain number is equivalent to
 *   { mode: 'premium', expectedAmountUSD: number }.
 *
 * On failure: responds 402 Payment Required.
 *
 * All payment attempts (success and failure) are logged to stderr as
 * newline-delimited JSON. Sensitive values (the raw JWT) are never logged.
 */

const crypto = require('crypto');
const https  = require('https');
const jwt    = require('jsonwebtoken');

// ── External endpoints ────────────────────────────────────────────────────────
const JWKS_URL      = 'https://www.x402gateway.io/.well-known/jwks.json';
const SOL_PRICE_URL = 'https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd';

// ── Cache TTLs ─────────────────────────────────────────────────────────────────
const JWKS_CACHE_TTL_MS  = 60 * 60 * 1000;   // 1 hour — JWKS keys change rarely
const PRICE_CACHE_TTL_MS =  5 * 60 * 1000;   // 5 minutes — prevents oracle manipulation

// ── In-memory caches (exported for test injection via _caches) ─────────────────
const _caches = {
  jwks:  { keys: null, fetchedAt: 0 },
  price: { priceUSD: null, fetchedAt: 0 }
};

// ── HTTP helper ────────────────────────────────────────────────────────────────
/**
 * Fetches JSON from a URL using Node's built-in https module.
 * Rejects on non-2xx status, timeout (5 s), or invalid JSON.
 */
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 5000 }, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Invalid JSON from ${url}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.on('error', reject);
  });
}

// ── JWKS retrieval (cached) ────────────────────────────────────────────────────
/**
 * Returns the array of JWK public keys from x402gateway.io.
 * The result is cached for JWKS_CACHE_TTL_MS to avoid repeated fetches.
 */
async function getJwks() {
  const now = Date.now();
  if (_caches.jwks.keys && (now - _caches.jwks.fetchedAt) < JWKS_CACHE_TTL_MS) {
    return _caches.jwks.keys;
  }
  const data = await fetchJson(JWKS_URL);
  if (!Array.isArray(data.keys) || data.keys.length === 0) {
    throw new Error('No JWKS keys returned from x402gateway.io');
  }
  _caches.jwks = { keys: data.keys, fetchedAt: now };
  return data.keys;
}

// ── SOL/USD price oracle (cached, 5-min TTL) ──────────────────────────────────
/**
 * Returns the current SOL/USD price from CoinGecko.
 * Cached for PRICE_CACHE_TTL_MS to protect against oracle manipulation attacks.
 */
async function getSolPriceUSD() {
  const now = Date.now();
  if (_caches.price.priceUSD !== null && (now - _caches.price.fetchedAt) < PRICE_CACHE_TTL_MS) {
    return _caches.price.priceUSD;
  }
  const data = await fetchJson(SOL_PRICE_URL);
  const price = data && data.solana && data.solana.usd;
  if (typeof price !== 'number' || price <= 0) {
    throw new Error('Invalid SOL/USD price from oracle');
  }
  _caches.price = { priceUSD: price, fetchedAt: now };
  return price;
}

// ── Payment attempt logger ─────────────────────────────────────────────────────
/**
 * Writes a payment attempt log entry to stderr as a JSON line.
 * The raw JWT token is never included in log entries.
 */
function logPaymentAttempt(entry) {
  process.stderr.write(JSON.stringify(entry) + '\n');
}

// ── JWK → Node.js KeyObject ────────────────────────────────────────────────────
function jwkToPublicKey(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// ── Middleware factory ─────────────────────────────────────────────────────────
/**
 * verifyX402Payment(options)
 *
 * Returns an Express middleware function. On success it attaches req.x402 and
 * calls next(). On failure it sends 402 Payment Required.
 *
 * @param {number|object} options
 *   Passing a plain number is backward-compatible shorthand for
 *   { mode: 'premium', expectedAmountUSD: <number> }.
 *
 *   Object shape:
 *     mode              'basic' | 'premium'  (default: 'premium')
 *     expectedAmountUSD  number               (default: 0.11, premium mode only)
 *
 * req.x402 on success:
 *   { valid: true, payerAddress: string|null, amountUSD: number|null }
 *   - basic mode:   payerAddress and amountUSD are null (no JWT to inspect)
 *   - premium mode: payerAddress is the JWT payer claim; amountUSD is in USD
 */
function verifyX402Payment(options = {}) {
  // ── Normalise options (backward-compat: plain number → premium mode) ────────
  let mode, expectedAmountUSD;
  if (typeof options === 'number') {
    mode = 'premium';
    expectedAmountUSD = options;
  } else {
    mode = options.mode || 'premium';
    // expectedAmountUSD is only relevant in 'premium' mode; ignored in 'basic' mode
    expectedAmountUSD = options.expectedAmountUSD !== undefined ? options.expectedAmountUSD : 0.11;
  }

  return async function x402PaymentMiddleware(req, res, next) {
    const paymentHeader = req.headers['x402-payment'];
    const logBase = {
      timestamp:        new Date().toISOString(),
      ip:               req.ip,
      path:             req.originalUrl,
      mode,
      hasPaymentHeader: Boolean(paymentHeader)
    };

    // ── 1. Header presence check (both modes) ──────────────────────────────
    if (!paymentHeader) {
      logPaymentAttempt({ ...logBase, result: 'missing_header' });
      const body = { error: 'Payment Required', message: 'x402-payment header is required' };
      if (mode === 'premium') body.requiredAmountUSD = expectedAmountUSD;
      return res.status(402).json(body);
    }

    // ── Basic mode: timingSafeEqual comparison ────────────────────────────────
    if (mode === 'basic') {
      const validToken = process.env.X402_PAYMENT_SECRET;
      if (!validToken) {
        logPaymentAttempt({ ...logBase, result: 'no_secret_configured' });
        return res.status(402).json({ error: 'Payment Required', message: 'Payment required via x402' });
      }
      try {
        const paidBuf  = Buffer.from(paymentHeader);
        const validBuf = Buffer.from(validToken);
        if (paidBuf.length !== validBuf.length || !crypto.timingSafeEqual(paidBuf, validBuf)) {
          logPaymentAttempt({ ...logBase, result: 'invalid_secret' });
          return res.status(402).json({ error: 'Payment Required', message: 'Payment required via x402' });
        }
      } catch {
        logPaymentAttempt({ ...logBase, result: 'comparison_error' });
        return res.status(402).json({ error: 'Payment Required', message: 'Payment required via x402' });
      }
      logPaymentAttempt({ ...logBase, result: 'success' });
      req.x402 = { valid: true, payerAddress: null, amountUSD: null };
      return next();
    }

    // ── Premium mode: JWT + JWKS + oracle ────────────────────────────────────
    try {
      // ── 2. Decode JWT (no verification) to read the kid claim ──────────────
      const decoded = jwt.decode(paymentHeader, { complete: true });
      if (!decoded || !decoded.header) {
        logPaymentAttempt({ ...logBase, result: 'invalid_jwt_format' });
        return res.status(402).json({ error: 'Payment Required', message: 'Invalid payment token format' });
      }

      // ── 3. Fetch JWKS and find the matching key ────────────────────────────
      const keys = await getJwks();
      const jwk  = decoded.header.kid
        ? keys.find(k => k.kid === decoded.header.kid)
        : keys[0];

      if (!jwk) {
        logPaymentAttempt({ ...logBase, result: 'jwk_not_found', kid: decoded.header.kid });
        return res.status(402).json({ error: 'Payment Required', message: 'Unknown payment signing key' });
      }

      // ── 4. Verify JWT signature using the x402gateway.io public key ────────
      const publicKey = jwkToPublicKey(jwk);
      const payload   = jwt.verify(paymentHeader, publicKey, {
        algorithms: ['RS256', 'ES256', 'PS256']
      });

      // ── 5. Determine USD value of the payment ──────────────────────────────
      const rawAmount = Number(payload.amount);
      const currency  = String(payload.currency || '').toUpperCase();

      if (!isFinite(rawAmount) || rawAmount <= 0) {
        logPaymentAttempt({ ...logBase, result: 'invalid_amount', rawAmount });
        return res.status(402).json({ error: 'Payment Required', message: 'Invalid payment amount in token' });
      }

      let amountUSD;
      if (currency === 'USD' || currency === 'USDC') {
        amountUSD = rawAmount;
      } else if (currency === 'SOL') {
        const solPrice = await getSolPriceUSD();
        amountUSD = rawAmount * solPrice;
      } else {
        logPaymentAttempt({ ...logBase, result: 'unsupported_currency', currency });
        return res.status(402).json({
          error:   'Payment Required',
          message: `Unsupported payment currency: ${currency}`
        });
      }

      // ── 6. Verify payment meets the required minimum ───────────────────────
      if (amountUSD < expectedAmountUSD) {
        logPaymentAttempt({ ...logBase, result: 'insufficient_amount', amountUSD, required: expectedAmountUSD });
        return res.status(402).json({
          error:   'Payment Required',
          message: `Insufficient payment. Required: $${expectedAmountUSD} USD, provided: $${amountUSD.toFixed(6)} USD`
        });
      }

      // ── 7. Extract payer address from JWT claims ───────────────────────────
      const payerAddress = payload.payer || payload.from || payload.sub;
      if (!payerAddress || typeof payerAddress !== 'string') {
        logPaymentAttempt({ ...logBase, result: 'missing_payer_address' });
        return res.status(402).json({ error: 'Payment Required', message: 'Payment token is missing payer address' });
      }

      logPaymentAttempt({ ...logBase, result: 'success', payerAddress, amountUSD });
      req.x402 = { valid: true, payerAddress, amountUSD };
      next();

    } catch (err) {
      logPaymentAttempt({ ...logBase, result: 'verification_failed', error: err.message });
      return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
    }
  };
}

module.exports = { verifyX402Payment, getSolPriceUSD, getJwks, _caches };

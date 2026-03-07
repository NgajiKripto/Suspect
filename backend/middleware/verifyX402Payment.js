'use strict';

/**
 * verifyX402Payment — x402 payment middleware for suspected.dev
 *
 * Validates the `x402-payment` JWT header by:
 *   1. Decoding the JWT and locating the signing key via x402gateway.io JWKS
 *   2. Verifying the JWT signature with the fetched public key
 *   3. Converting the payment amount to USD (SOL/USD oracle, 5-min cached TTL)
 *   4. Checking amount >= expectedAmountUSD
 *   5. Extracting the payer address from JWT claims
 *
 * On success: attaches req.x402 = { valid: true, payerAddress: string }
 * On failure: responds 402 Payment Required
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
 * verifyX402Payment(expectedAmountUSD = 0.11)
 *
 * Returns an Express middleware function. On success it attaches:
 *   req.x402 = { valid: true, payerAddress: string }
 *
 * and calls next(). On failure it sends 402 Payment Required.
 *
 * @param {number} expectedAmountUSD  Minimum USD payment required (default: 0.11)
 */
function verifyX402Payment(expectedAmountUSD = 0.11) {
  return async function x402PaymentMiddleware(req, res, next) {
    const paymentHeader = req.headers['x402-payment'];
    const logBase = {
      timestamp:        new Date().toISOString(),
      ip:               req.ip,
      path:             req.originalUrl,
      hasPaymentHeader: Boolean(paymentHeader)
    };

    // ── 1. Header presence check ─────────────────────────────────────────────
    if (!paymentHeader) {
      logPaymentAttempt({ ...logBase, result: 'missing_header' });
      return res.status(402).json({
        error:              'Payment Required',
        message:            'x402-payment header is required',
        requiredAmountUSD:  expectedAmountUSD
      });
    }

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
      req.x402 = { valid: true, payerAddress };
      next();

    } catch (err) {
      logPaymentAttempt({ ...logBase, result: 'verification_failed', error: err.message });
      return res.status(402).json({ error: 'Payment Required', message: 'Payment verification failed' });
    }
  };
}

module.exports = { verifyX402Payment, getSolPriceUSD, getJwks, _caches };

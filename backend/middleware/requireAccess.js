'use strict';

/**
 * requireAccess — unified access-control middleware factory for suspected.dev
 *
 * Factory function that returns an Express middleware enforcing one of three
 * access levels:
 *
 *   level: 'public'
 *     → No authentication required. Always calls next().
 *       Use for endpoints that are open to everyone.
 *
 *   level: 'premium'
 *     → Requires a valid x402 payment (JWT + JWKS + price oracle).
 *       Delegates to verifyX402Payment({ mode: 'premium', expectedAmountUSD }).
 *       On success: sets req.hasPremiumAccess = true and calls next().
 *       On failure: 402 Payment Required (sent by verifyX402Payment).
 *       options.amountUSD — required payment in USD (default: 0.11)
 *
 *   level: 'admin'
 *     → Requires EITHER a valid Telegram admin token OR a valid admin JWT,
 *       depending on options.adminSources (default: ['jwt']).
 *       Sources are tried in order; the first that succeeds grants access.
 *       On success: sets req.isAdmin = true, req.adminAuth = { source, payerAddress? }
 *       On failure: 401 if no credentials were provided at all, 403 otherwise.
 *       options.adminSources — array containing 'telegram' and/or 'jwt'
 *
 * Error responses:
 *   402  Payment Required      — premium payment missing or invalid
 *   401  Authentication needed — admin: no auth credentials provided
 *   403  Forbidden             — admin: credentials present but insufficient
 *
 * Usage:
 *   const { requireAccess } = require('./middleware/requireAccess');
 *
 *   // Public endpoint
 *   app.get('/api/wallets', requireAccess('public'), handler);
 *
 *   // Premium-gated endpoint
 *   app.get('/api/wallets/:id/data', requireAccess('premium', { amountUSD: 0.11 }), handler);
 *
 *   // Admin-only endpoint (Telegram token OR JWT)
 *   app.patch('/api/admin/wallets/:id/premium',
 *     requireAccess('admin', { adminSources: ['telegram', 'jwt'] }), handler);
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const { verifyX402Payment, getJwks } = require('./verifyX402Payment');
const { writeAuditLog }              = require('../auditLog');

// ── Private helper: log an unauthorized admin attempt ────────────────────────
function logUnauthorized(entry) {
  writeAuditLog({ ...entry, event: 'unauthorized_admin_attempt' });
}

// ── requireAccess factory ─────────────────────────────────────────────────────
function requireAccess(level, options = {}) {

  // ── 'public': no auth required ────────────────────────────────────────────
  if (level === 'public') {
    return function publicAccessMiddleware(_req, _res, next) {
      next();
    };
  }

  // ── 'premium': x402 payment required ─────────────────────────────────────
  if (level === 'premium') {
    const amountUSD = options.amountUSD !== undefined ? options.amountUSD : 0.11;
    const premiumMiddleware = verifyX402Payment({
      mode: 'premium',
      expectedAmountUSD: amountUSD
    });

    return function premiumAccessMiddleware(req, res, next) {
      premiumMiddleware(req, res, function onPaymentVerified() {
        req.hasPremiumAccess = true;
        next();
      });
    };
  }

  // ── 'admin': Telegram token OR JWT required ───────────────────────────────
  if (level === 'admin') {
    const adminSources = Array.isArray(options.adminSources)
      ? options.adminSources
      : ['jwt'];

    return async function adminAccessMiddleware(req, res, next) {
      const timestamp = new Date().toISOString();
      const ip        = req.ip;
      const action    = `${req.method} ${req.originalUrl}`;

      // Track whether the caller presented ANY admin credential header so we
      // can differentiate 401 (no credentials) from 403 (wrong credentials).
      let anyHeaderPresent = false;

      // ── Source: 'telegram' — x-telegram-admin-token timingSafeEqual ───────
      if (adminSources.includes('telegram')) {
        const tgToken        = req.headers['x-telegram-admin-token'];
        const configuredToken = process.env.TELEGRAM_ADMIN_TOKEN;

        if (tgToken) {
          anyHeaderPresent = true;
          if (configuredToken) {
            try {
              const aBuf = Buffer.from(tgToken);
              const bBuf = Buffer.from(configuredToken);
              if (aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf)) {
                req.isAdmin   = true;
                req.adminAuth = { source: 'telegram' };
                return next();
              }
            } catch { /* fall through to next source */ }
          }
        }
      }

      // ── Source: 'jwt' — x402-payment JWT + JWKS + admin wallet whitelist ──
      if (adminSources.includes('jwt')) {
        const paymentHeader = req.headers['x402-payment'];

        if (paymentHeader) {
          anyHeaderPresent = true;
          try {
            // 1. Decode JWT to read the kid claim (no signature check yet)
            const decoded = jwt.decode(paymentHeader, { complete: true });
            if (!decoded || !decoded.header) {
              logUnauthorized({ source: 'api', reason: 'invalid_jwt_format', ip, timestamp, action });
              return res.status(403).json({ success: false, message: 'Forbidden' });
            }

            // 2. Fetch JWKS and locate the matching key
            const keys = await getJwks();
            const jwk  = decoded.header.kid
              ? keys.find(k => k.kid === decoded.header.kid)
              : keys[0];

            if (!jwk) {
              logUnauthorized({ source: 'api', reason: 'jwk_not_found', ip, timestamp, action });
              return res.status(403).json({ success: false, message: 'Forbidden' });
            }

            // 3. Verify JWT signature — algorithm list mirrors requireAdminAuth
            const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            const payload   = jwt.verify(paymentHeader, publicKey, {
              algorithms: ['RS256', 'ES256', 'PS256']
            });

            // 4. Extract payer address from JWT claims
            const payerAddress = payload.payer || payload.from || payload.sub;
            if (!payerAddress || typeof payerAddress !== 'string') {
              logUnauthorized({ source: 'api', reason: 'missing_payer_address', ip, timestamp, action });
              return res.status(403).json({ success: false, message: 'Forbidden' });
            }

            // 5. Verify payer is in the admin wallet whitelist
            const adminAddresses = (process.env.ADMIN_WALLET_ADDRESSES || '')
              .split(',')
              .map(a => a.trim())
              .filter(Boolean);

            if (adminAddresses.length === 0 || !adminAddresses.includes(payerAddress)) {
              logUnauthorized({ source: 'api', reason: 'payer_not_in_whitelist', ip, payerAddress, timestamp, action });
              return res.status(403).json({ success: false, message: 'Forbidden' });
            }

            req.isAdmin   = true;
            req.adminAuth = { source: 'api', payerAddress };
            return next();

          } catch (err) {
            logUnauthorized({ source: 'api', reason: 'jwt_verification_failed', error: err.message, ip, timestamp, action });
            return res.status(403).json({ success: false, message: 'Forbidden' });
          }
        }
      }

      // ── No valid admin credentials found ───────────────────────────────────
      logUnauthorized({
        source:    'api',
        reason:    anyHeaderPresent ? 'invalid_credentials' : 'missing_credentials',
        ip,
        timestamp,
        action
      });

      if (!anyHeaderPresent) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }
      return res.status(403).json({ success: false, message: 'Forbidden' });
    };
  }

  throw new Error(
    `requireAccess: invalid level "${level}". Must be 'public', 'premium', or 'admin'.`
  );
}

module.exports = { requireAccess };

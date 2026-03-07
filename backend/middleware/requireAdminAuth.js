'use strict';

/**
 * requireAdminAuth — reusable admin-only authorization middleware
 *
 * Factory function that returns an authorization handler for admin actions:
 *
 *   source = 'api'
 *     → Express middleware (req, res, next)
 *       1. Verifies the x402-payment JWT header via x402gateway.io JWKS
 *       2. Checks the payer address against process.env.ADMIN_WALLET_ADDRESSES
 *          (comma-separated list of allowed admin wallet addresses)
 *       3. Returns HTTP 403 Forbidden if either check fails
 *       4. On success, attaches req.adminAuth = { source: 'api', payerAddress }
 *
 *   source = 'telegram'
 *     → Sync function (msg) => boolean
 *       Works with both Message and CallbackQuery objects from node-telegram-bot-api.
 *       1. Verifies msg.chat.id (or msg.message.chat.id for CallbackQuery) equals
 *          process.env.TELEGRAM_ADMIN_CHAT_ID (falls back to TELEGRAM_CHAT_ID)
 *       2. If process.env.TELEGRAM_ADMIN_USER_IDS is configured (comma-separated),
 *          verifies msg.from.id is in that whitelist
 *       3. Returns false if either check fails; true on success
 *
 * Logging: every unauthorized attempt is appended to admin_audit.log as a JSON
 * line with source, reason, IP/chat.id, timestamp, and attempted action.
 * The raw payment token is never logged.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const jwt    = require('jsonwebtoken');
const { getJwks } = require('./verifyX402Payment');

// ── Audit log (same file used by server.js writeAdminAuditLog) ────────────────
const AUDIT_LOG_PATH = path.join(__dirname, '..', 'admin_audit.log');

function logUnauthorized(entry) {
  const line = JSON.stringify({ ...entry, event: 'unauthorized_admin_attempt' }) + '\n';
  fs.appendFile(AUDIT_LOG_PATH, line, (err) => {
    if (err) process.stderr.write(`[requireAdminAuth] audit log write failed: ${err.message}\n`);
  });
}

// ── requireAdminAuth factory ───────────────────────────────────────────────────
function requireAdminAuth(source = 'api') {

  // ── API: Express middleware ────────────────────────────────────────────────
  if (source === 'api') {
    return async function adminApiAuthMiddleware(req, res, next) {
      const timestamp = new Date().toISOString();
      const ip        = req.ip;
      const action    = `${req.method} ${req.originalUrl}`;

      // ── 1. x402-payment header must be present ───────────────────────────
      const paymentHeader = req.headers['x402-payment'];
      if (!paymentHeader) {
        logUnauthorized({ source: 'api', reason: 'missing_x402_payment', ip, timestamp, action });
        return res.status(403).json({ success: false, message: 'Forbidden' });
      }

      // ── 2. Verify the JWT signature via x402gateway.io JWKS ─────────────
      let payerAddress;
      try {
        const decoded = jwt.decode(paymentHeader, { complete: true });
        if (!decoded || !decoded.header) {
          logUnauthorized({ source: 'api', reason: 'invalid_jwt_format', ip, timestamp, action });
          return res.status(403).json({ success: false, message: 'Forbidden' });
        }

        const keys = await getJwks();
        const jwk  = decoded.header.kid
          ? keys.find(k => k.kid === decoded.header.kid)
          : keys[0];

        if (!jwk) {
          logUnauthorized({ source: 'api', reason: 'jwk_not_found', ip, timestamp, action });
          return res.status(403).json({ success: false, message: 'Forbidden' });
        }

        // Verify signature using the key from JWKS.
        // The algorithm list mirrors verifyX402Payment.js and matches x402gateway.io
        // conventions; the public-key type implicitly constrains which algorithm can
        // succeed, providing an additional layer against algorithm-confusion attacks.
        const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        const payload   = jwt.verify(paymentHeader, publicKey, {
          algorithms: ['RS256', 'ES256', 'PS256']
        });

        payerAddress = payload.payer || payload.from || payload.sub;
        if (!payerAddress || typeof payerAddress !== 'string') {
          logUnauthorized({ source: 'api', reason: 'missing_payer_address', ip, timestamp, action });
          return res.status(403).json({ success: false, message: 'Forbidden' });
        }
      } catch (err) {
        logUnauthorized({ source: 'api', reason: 'jwt_verification_failed', error: err.message, ip, timestamp, action });
        return res.status(403).json({ success: false, message: 'Forbidden' });
      }

      // ── 3. Verify payer is in the admin wallet whitelist ─────────────────
      const adminAddresses = (process.env.ADMIN_WALLET_ADDRESSES || '')
        .split(',')
        .map(a => a.trim())
        .filter(Boolean);

      if (adminAddresses.length === 0 || !adminAddresses.includes(payerAddress)) {
        logUnauthorized({ source: 'api', reason: 'payer_not_in_whitelist', ip, payerAddress, timestamp, action });
        return res.status(403).json({ success: false, message: 'Forbidden' });
      }

      req.adminAuth = { source: 'api', payerAddress };
      next();
    };
  }

  // ── Telegram: sync boolean handler ────────────────────────────────────────
  if (source === 'telegram') {
    return function telegramAdminAuthHandler(msg) {
      const timestamp = new Date().toISOString();

      // Support both Message objects (msg.chat.id) and CallbackQuery objects
      // (msg.message.chat.id) from node-telegram-bot-api
      const chatId = (msg && msg.chat && msg.chat.id) ||
                     (msg && msg.message && msg.message.chat && msg.message.chat.id);
      const fromId = msg && msg.from && msg.from.id;
      const action = (msg && msg.text) || (msg && msg.data) || '(unknown)';

      const adminChatId  = process.env.TELEGRAM_ADMIN_CHAT_ID || process.env.TELEGRAM_CHAT_ID;
      const adminUserIds = (process.env.TELEGRAM_ADMIN_USER_IDS || '')
        .split(',')
        .map(id => id.trim())
        .filter(Boolean);

      // ── 1. Verify chat.id ────────────────────────────────────────────────
      if (!adminChatId || String(chatId) !== String(adminChatId)) {
        logUnauthorized({ source: 'telegram', reason: 'invalid_chat_id', chatId, timestamp, action });
        return false;
      }

      // ── 2. Verify from.id against user whitelist (if configured) ─────────
      if (adminUserIds.length > 0 && !adminUserIds.includes(String(fromId))) {
        logUnauthorized({ source: 'telegram', reason: 'user_not_in_whitelist', chatId, fromId, timestamp, action });
        return false;
      }

      return true;
    };
  }

  throw new Error(`requireAdminAuth: invalid source "${source}". Must be 'api' or 'telegram'.`);
}

module.exports = { requireAdminAuth };

'use strict';

/**
 * HTML-encodes the five HTML-special characters so that API-supplied values
 * cannot inject markup when interpolated into template strings on the frontend.
 * Mirrors escapeHtml() from frontend/index.html.
 *
 * @param {*} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Recursively HTML-escapes all string values inside a plain object or array.
 * Numbers, booleans, null, undefined, and Date instances are returned as-is.
 *
 * @param {*} value
 * @returns {*}
 */
function deepEscape(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return escapeHtml(value);
  if (value instanceof Date) return value;
  if (Array.isArray(value)) return value.map(deepEscape);
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      out[key] = deepEscape(value[key]);
    }
    return out;
  }
  return value; // number, boolean, etc.
}

/**
 * Formats a wallet document for API responses with a consistent structure.
 *
 * Behaviour:
 *   - Always excludes __v and the raw `forensic` sub-document.
 *   - Conditionally includes `premiumForensics` only when
 *     `options.hasPremiumAccess === true`.
 *   - HTML-escapes every string value (XSS prevention for the rendering layer).
 *   - Formats each entry in `premiumForensics.tokensCreated` as
 *     `{ address, solscanLink }` for frontend convenience.
 *   - Appends `meta { hasPremiumData, lastPremiumUpdate }` so the frontend
 *     can render UI hints without having to inspect nested fields.
 *
 * @param {object} wallet  Mongoose document or plain wallet object.
 * @param {object} [options]
 * @param {boolean} [options.hasPremiumAccess=false]  Grant premium fields.
 * @returns {object}
 *
 * @example
 * // GET /api/wallets/:address
 * res.json(formatWalletResponse(wallet, { hasPremiumAccess: req.hasPremiumAccess === true }));
 *
 * @example
 * // GET /api/wallets (list)
 * res.json(wallets.map(w => formatWalletResponse(w)));
 *
 * @example
 * // PATCH /api/admin/wallets/:address/premium (success response)
 * res.json({ success: true, wallet: formatWalletResponse(wallet, { hasPremiumAccess: true }), auditLog });
 */
function formatWalletResponse(wallet, options = {}) {
  const hasPremiumAccess = options.hasPremiumAccess === true;

  // Convert Mongoose document to a plain object, stripping __v.
  const raw = typeof wallet.toObject === 'function'
    ? wallet.toObject({ versionKey: false })
    : { ...wallet };

  // Remove always-excluded fields.
  // `__v` is stripped via versionKey:false / destructuring.
  // `forensic` holds raw internal evidence that is never surfaced publicly.
  // `premiumForensics` is handled separately below.
  const { __v, forensic, premiumForensics: rawPremium, ...pub } = raw;

  // Deep-escape all string values in the public portion.
  const result = deepEscape(pub);

  // Attach frontend UI hints.
  result.meta = {
    hasPremiumData: hasPremiumAccess && rawPremium != null,
    lastPremiumUpdate:
      hasPremiumAccess && rawPremium != null && rawPremium.updatedAt != null
        ? rawPremium.updatedAt
        : null
  };

  // Conditionally include premium forensics with enhanced formatting.
  if (hasPremiumAccess && rawPremium != null) {
    const { tokensCreated, ...restPremium } = rawPremium;

    // Escape all scalar string fields in premiumForensics.
    const escapedPremium = deepEscape(restPremium);

    // Format tokensCreated as { address, solscanLink } objects for the frontend.
    if (Array.isArray(tokensCreated)) {
      escapedPremium.tokensCreated = tokensCreated.map(addr => {
        const rawAddr  = String(addr);
        const safeAddr = escapeHtml(rawAddr);
        // Build the URL from the raw address so it is a valid URL;
        // the address display field is HTML-escaped separately.
        return { address: safeAddr, solscanLink: `https://solscan.io/token/${rawAddr}` };
      });
    } else {
      escapedPremium.tokensCreated = [];
    }

    result.premiumForensics = escapedPremium;
  }

  return result;
}

module.exports = { formatWalletResponse, escapeHtml };

'use strict';

// ─── Shared validation regex (mirrors server.js constants) ───────────────────
const WALLET_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const LIQUIDITY_VALUE_REGEX = /^\d+(\.\d+)?\s*(SOL|USDC|USD)?$/i;
const HTML_TAG_REGEX = /<[^>]*>/;

/**
 * Short-key to camelCase field name mapping used when parsing admin text input.
 *
 * ADD_LIQ → addLiquidityValue
 * REM_LIQ → removeLiquidityValue
 * FUNDING → walletFunding
 * TOKENS  → tokensCreated
 * NOTES   → forensicNotes
 * LINKS   → crossProjectLinks
 */
const PREMIUM_INPUT_KEYS = {
  ADD_LIQ: 'addLiquidityValue',
  REM_LIQ: 'removeLiquidityValue',
  FUNDING: 'walletFunding',
  TOKENS:  'tokensCreated',
  NOTES:   'forensicNotes',
  LINKS:   'crossProjectLinks'
};

/**
 * Parse structured premium text input into a plain data object.
 *
 * Lines must follow the format:  KEY: value
 * TOKENS and LINKS values are split on commas to produce arrays.
 * Unrecognised keys are silently ignored.
 *
 * @param {string} text
 * @returns {{ addLiquidityValue?: string, removeLiquidityValue?: string,
 *             walletFunding?: string, tokensCreated?: string[],
 *             forensicNotes?: string, crossProjectLinks?: string[] }}
 */
function parsePremiumInput(text) {
  if (typeof text !== 'string') return {};

  const result = {};

  for (const line of text.split('\n')) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;

    const rawKey    = line.substring(0, colonIdx).trim().toUpperCase();
    const value     = line.substring(colonIdx + 1).trim();
    const fieldName = PREMIUM_INPUT_KEYS[rawKey];

    // Skip lines with no value — admins may send partial templates with blank fields
    if (fieldName && value.length > 0) result[fieldName] = value;
  }

  // Split comma-separated strings into arrays for array fields
  if (typeof result.tokensCreated === 'string') {
    result.tokensCreated = result.tokensCreated.split(',').map(s => s.trim()).filter(Boolean);
  }
  if (typeof result.crossProjectLinks === 'string') {
    result.crossProjectLinks = result.crossProjectLinks.split(',').map(s => s.trim()).filter(Boolean);
  }

  return result;
}

/**
 * Validate parsed premium fields against the same rules enforced by
 * PATCH /api/admin/wallets/:address/premium.
 *
 * @param {Object}   data  Output of parsePremiumInput()
 * @returns {string[]}     Human-readable error messages (empty array = valid)
 */
function validatePremiumFields(data) {
  const errors = [];

  if (data.addLiquidityValue !== undefined) {
    if (typeof data.addLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(data.addLiquidityValue)) {
      errors.push('ADD_LIQ must be a number optionally followed by SOL, USDC, or USD (e.g. 45.2 SOL)');
    }
  }

  if (data.removeLiquidityValue !== undefined) {
    if (typeof data.removeLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(data.removeLiquidityValue)) {
      errors.push('REM_LIQ must be a number optionally followed by SOL, USDC, or USD (e.g. 0.3 SOL)');
    }
  }

  if (data.walletFunding !== undefined) {
    if (
      typeof data.walletFunding !== 'string' ||
      data.walletFunding.length > 200 ||
      HTML_TAG_REGEX.test(data.walletFunding)
    ) {
      errors.push('FUNDING must be a plain string, max 200 chars, with no HTML tags');
    }
  }

  if (data.tokensCreated !== undefined) {
    if (
      !Array.isArray(data.tokensCreated) ||
      !data.tokensCreated.every(addr => typeof addr === 'string' && WALLET_ADDRESS_REGEX.test(addr))
    ) {
      errors.push('TOKENS must be comma-separated valid Solana Base58 addresses (32–44 chars each)');
    }
  }

  if (data.forensicNotes !== undefined) {
    if (typeof data.forensicNotes !== 'string') {
      errors.push('NOTES must be a string');
    }
  }

  if (data.crossProjectLinks !== undefined) {
    if (
      !Array.isArray(data.crossProjectLinks) ||
      !data.crossProjectLinks.every(addr => typeof addr === 'string' && WALLET_ADDRESS_REGEX.test(addr))
    ) {
      errors.push('LINKS must be comma-separated valid Solana Base58 addresses (32–44 chars each)');
    }
  }

  return errors;
}

/**
 * Build a human-readable confirmation preview message for the admin.
 *
 * @param {number|string} caseNumber
 * @param {string}        walletAddress
 * @param {Object}        parsed  Output of parsePremiumInput()
 * @returns {string}
 */
function buildPremiumPreview(caseNumber, walletAddress, parsed) {
  const fmt = (val) => {
    if (val === undefined || val === null) return '(not set)';
    return Array.isArray(val) ? val.join(', ') : String(val);
  };

  return [
    `🔐 Premium Data Preview — Case #${caseNumber}`,
    `Wallet: ${walletAddress}`,
    '',
    `ADD_LIQ:  ${fmt(parsed.addLiquidityValue)}`,
    `REM_LIQ:  ${fmt(parsed.removeLiquidityValue)}`,
    `FUNDING:  ${fmt(parsed.walletFunding)}`,
    `TOKENS:   ${fmt(parsed.tokensCreated)}`,
    `NOTES:    ${fmt(parsed.forensicNotes)}`,
    `LINKS:    ${fmt(parsed.crossProjectLinks)}`,
    '',
    'Confirm to save this data?'
  ].join('\n');
}

/** Help text shown by the /premium_help admin command. */
const PREMIUM_HELP_TEXT = `📖 Premium Forensic Data Format

Send a message in this exact format after clicking [📝 Add Premium Data] on a case:

ADD_LIQ: 45.2 SOL
REM_LIQ: 0.3 SOL
FUNDING: CEX withdrawal (Binance)
TOKENS: Token1Addr,Token2Addr
NOTES: Repeated rugpull pattern across 3 projects
LINKS: RelatedWallet1,RelatedWallet2

Field rules:
• ADD_LIQ / REM_LIQ — number followed by optional SOL, USDC, or USD (e.g. 45.2 SOL)
• FUNDING — plain text, max 200 chars, no HTML tags
• TOKENS — comma-separated Solana Base58 addresses (32–44 chars each)
• NOTES — free-form text description of forensic findings
• LINKS — comma-separated related wallet addresses (32–44 chars each)

All fields are optional. Only provided fields will be updated.
Use /premium_help at any time to see this format again.`;

/**
 * Reverse of PREMIUM_INPUT_KEYS: camelCase field name → short display key.
 *
 * addLiquidityValue   → ADD_LIQ
 * removeLiquidityValue → REM_LIQ
 * walletFunding       → FUNDING
 * tokensCreated       → TOKENS
 * forensicNotes       → NOTES
 * crossProjectLinks   → LINKS
 */
const CAMEL_TO_KEY = Object.fromEntries(
  Object.entries(PREMIUM_INPUT_KEYS).map(([displayKey, camelField]) => [camelField, displayKey])
);

/**
 * Set of camelCase field names that are considered sensitive and require
 * extra re-confirmation before saving.
 */
const SENSITIVE_FIELDS = new Set(['walletFunding', 'crossProjectLinks']);

/**
 * Build a human-readable message showing the current premium forensic values
 * for a wallet, with ✏️ indicators for each editable field.
 *
 * @param {number|string} caseNumber
 * @param {string}        walletAddress
 * @param {Object}        data  Current premiumForensics data
 * @returns {string}
 */
function buildEditCurrentValues(caseNumber, walletAddress, data) {
  const fmt = (val) => {
    if (val === undefined || val === null) return '(not set)';
    return Array.isArray(val) ? val.join(', ') : String(val);
  };

  return [
    `📋 Current premium data for Case #${caseNumber}:`,
    `Wallet: ${walletAddress}`,
    '',
    `ADD_LIQ: ${fmt(data.addLiquidityValue)} [✏️]`,
    `REM_LIQ: ${fmt(data.removeLiquidityValue)} [✏️]`,
    `FUNDING: ${fmt(data.walletFunding)} [✏️]`,
    `TOKENS: ${fmt(data.tokensCreated)} [✏️]`,
    `NOTES: ${fmt(data.forensicNotes)} [✏️]`,
    `LINKS: ${fmt(data.crossProjectLinks)} [✏️]`,
    '',
    'Click ✏️ next to any field to update, or send NEW_VALUES: ... to replace all'
  ].join('\n');
}

/**
 * Build a diff preview message for a single-field change.
 *
 * @param {number|string} caseNumber
 * @param {string}        fieldLabel  Short display key, e.g. 'FUNDING'
 * @param {*}             oldValue    Current stored value
 * @param {*}             newValue    Proposed new value
 * @param {boolean}       [isSensitive=false]
 * @returns {string}
 */
function buildDiffPreview(caseNumber, fieldLabel, oldValue, newValue, isSensitive = false) {
  const fmt = (val) => {
    if (val === undefined || val === null) return '(not set)';
    return Array.isArray(val) ? val.join(', ') : String(val);
  };

  const lines = [
    `🔄 Diff Preview — Case #${caseNumber}`,
    '',
    `Change ${fieldLabel}:`,
    `  From: '${fmt(oldValue)}'`,
    `  To:   '${fmt(newValue)}'`
  ];

  if (isSensitive) {
    lines.push('', '⚠️  This is a sensitive field. Please confirm carefully.');
  }

  lines.push('', 'Confirm this change?');
  return lines.join('\n');
}

/**
 * Build a diff preview message for a bulk (multi-field) update.
 * Only fields that actually differ from the current stored values are listed.
 *
 * @param {number|string} caseNumber
 * @param {string}        walletAddress
 * @param {Object}        currentData  Current premiumForensics values
 * @param {Object}        newData      Parsed input from parsePremiumInput()
 * @returns {string}
 */
function buildBulkDiffPreview(caseNumber, walletAddress, currentData, newData) {
  const fmt = (val) => {
    if (val === undefined || val === null) return '(not set)';
    return Array.isArray(val) ? val.join(', ') : String(val);
  };

  const lines = [
    `🔄 Bulk Update Preview — Case #${caseNumber}`,
    `Wallet: ${walletAddress}`,
    '',
    'Changes:'
  ];

  let changeCount = 0;
  for (const [camel, label] of Object.entries(CAMEL_TO_KEY)) {
    if (newData[camel] !== undefined) {
      const oldStr = fmt(currentData[camel]);
      const newStr = fmt(newData[camel]);
      lines.push(`  ${label}: '${oldStr}' → '${newStr}'`);
      changeCount++;
    }
  }

  if (changeCount === 0) {
    lines.push('  (no recognised fields provided)');
  }

  lines.push('', 'Confirm all changes?');
  return lines.join('\n');
}

module.exports = {
  parsePremiumInput,
  validatePremiumFields,
  buildPremiumPreview,
  PREMIUM_HELP_TEXT,
  PREMIUM_INPUT_KEYS,
  CAMEL_TO_KEY,
  SENSITIVE_FIELDS,
  buildEditCurrentValues,
  buildDiffPreview,
  buildBulkDiffPreview
};

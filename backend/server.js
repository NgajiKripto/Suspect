require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const TelegramBot = require('node-telegram-bot-api');

const Wallet = require('./models/wallet');
const { verifyX402Payment } = require('./middleware/verifyX402Payment');
const { requireAdminAuth } = require('./middleware/requireAdminAuth');
const { requireAccess } = require('./middleware/requireAccess');
const { writeAuditLog, hashIp, AUDIT_LOG_PATH } = require('./auditLog');
const { formatWalletResponse } = require('./utils/response');
const {
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
} = require('./botUtils');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://suspected.dev',
  methods: ['GET', 'POST', 'PATCH'],
  allowedHeaders: ['Content-Type', 'x402-payment', 'x-admin-token', 'x-telegram-admin-token']
}));
app.use(express.json());

app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Stricter rate limit for report submission — prevents spam and Telegram flood
const submitRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many reports submitted. Please try again later.' }
});

// Rate limit for admin premium update endpoint — max 20 per hour per admin token
const adminPremiumRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => {
    const token = req.headers['x-telegram-admin-token'] || req.headers['x402-payment'] || req.ip;
    // Hash the token so the raw credential is not stored as a rate-limit key in memory
    return crypto.createHash('sha256').update(String(token)).digest('hex');
  },
  message: { success: false, message: 'Rate limit exceeded. Max 20 updates per hour per admin token.' }
});

// Validation patterns for premiumForensics fields
const LIQUIDITY_VALUE_REGEX = /^\d+(\.\d+)?\s*(SOL|USDC|USD)?$/i;
const HTML_TAG_REGEX = /<[^>]*>/;

/**
 * ==========================
 * DATABASE
 * ==========================
 */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });

/**
 * ==========================
 * TELEGRAM BOT
 * ==========================
 */
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
const chatId = process.env.TELEGRAM_CHAT_ID;

// Reusable admin authorization handler for Telegram callbacks and messages
const telegramAdminAuth = requireAdminAuth('telegram');

// Tracks which wallet an admin is currently entering premium data for (chatId → pending entry)
const pendingPremiumEntry = new Map();
// Stores parsed premium data awaiting admin confirmation (confirmKey → confirmation info)
const pendingPremiumData = new Map();

// ── /edit_premium state ────────────────────────────────────────────────────
// Tracks an active field-edit prompt: chatId → { walletId, walletAddress, caseNumber, fieldName, oldValue, timeoutId }
const pendingFieldEdit = new Map();
// Stores single-field diff awaiting confirmation: confirmKey → { walletId, walletAddress, caseNumber, fieldName, oldValue, newValue }
const pendingEditConfirm = new Map();
// Stores bulk-field diff awaiting confirmation: confirmKey → { walletId, walletAddress, caseNumber, currentData, parsed }
const pendingBulkEdit = new Map();

// Per-admin edit rate limiter: chatId → { count, windowStart }
const adminEditRateLimiter = new Map();
const EDIT_RATE_LIMIT     = 5;
const EDIT_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour

/**
 * Check and increment the per-admin edit rate limit.
 * Returns true if the action is allowed; false if the limit has been exceeded.
 */
function checkAdminEditRateLimit(adminChatId) {
  const now   = Date.now();
  const entry = adminEditRateLimiter.get(adminChatId);
  if (!entry || now - entry.windowStart > EDIT_RATE_WINDOW_MS) {
    adminEditRateLimiter.set(adminChatId, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= EDIT_RATE_LIMIT) return false;
  entry.count++;
  return true;
}

// STEP 1: Admin receives report notification with 4-button inline keyboard
const requestForensicInput = async (wallet) => {
  await bot.sendMessage(
    chatId,
    `📋 New Report — Case #${wallet.caseNumber}\n\n📍 Wallet: ${wallet.walletAddress}\n📝 ${wallet.evidence?.description || '(no description)'}\n\nIsi forensic data dan gunakan tombol di bawah:`,
    {
      reply_markup: {
        inline_keyboard: [
          [
            { text: '🔍 Review',           callback_data: `review_${wallet._id}` },
            { text: '✅ Verify',           callback_data: `verify_${wallet._id}` }
          ],
          [
            { text: '❌ Reject',           callback_data: `reject_${wallet._id}` },
            { text: '📝 Add Premium Data', callback_data: `addpremium_${wallet._id}` }
          ]
        ]
      }
    }
  );
};

// STEP 2: Admin submit forensic via bot
bot.on('message', async (msg) => {
  // Only process messages from the authorized chat
  if (String(msg.chat.id) !== String(chatId)) return;

  if (!msg.text.includes('LiquidityBefore')) return;

  const lines = msg.text.split('\n');
  const data = {};

  lines.forEach(line => {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) return;
    const key = line.substring(0, colonIndex).trim();
    const value = line.substring(colonIndex + 1).trim();
    if (key && value) data[key] = value;
  });

  const wallet = await Wallet.findOne({ status: 'pending' })
    .sort({ createdAt: -1 });

  if (!wallet) return;

  wallet.forensic = {
    liquidityBefore: Number(data.LiquidityBefore),
    liquidityAfter: Number(data.LiquidityAfter),
    drainDurationHours: Number(data.DrainDurationHours),
    detectedPattern: data.DetectedPattern?.split(',') || [],
    walletFunding: data.WalletFunding
  };

  await wallet.save();

  await bot.sendMessage(chatId,
    `Forensic saved. Klik verify.`,
    {
      reply_markup: {
        inline_keyboard: [[
          { text: '✅ Verify', callback_data: `verify_${wallet._id}` }
        ]]
      }
    }
  );
});

// STEP 2b: Admin submit premium forensics via bot
const ALLOWED_PREMIUM_KEYS = new Set([
  'AddLiquidityValue', 'RemoveLiquidityValue', 'WalletFunding',
  'TokensCreated', 'ForensicNotes', 'CrossProjectLinks', 'WalletId'
]);

bot.on('message', async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  if (!msg.text || !msg.text.includes('AddLiquidityValue')) return;
  if (!msg.text.includes('WalletId')) return;

  const lines = msg.text.split('\n');
  const data = {};

  lines.forEach(line => {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) return;
    const key = line.substring(0, colonIndex).trim();
    const value = line.substring(colonIndex + 1).trim();
    if (key && value && ALLOWED_PREMIUM_KEYS.has(key)) data[key] = value;
  });

  if (!data.WalletId) return;

  const wallet = await Wallet.findById(data.WalletId);
  if (!wallet) {
    await bot.sendMessage(chatId, `❌ Wallet ID tidak ditemukan: ${data.WalletId}`);
    return;
  }

  wallet.set('premiumForensics', {
    addLiquidityValue: data.AddLiquidityValue || null,
    removeLiquidityValue: data.RemoveLiquidityValue || null,
    walletFunding: data.WalletFunding || null,
    tokensCreated: data.TokensCreated ? data.TokensCreated.split(',').map(s => s.trim()).filter(Boolean) : [],
    forensicNotes: data.ForensicNotes || null,
    crossProjectLinks: data.CrossProjectLinks ? data.CrossProjectLinks.split(',').map(s => s.trim()).filter(Boolean) : [],
    updatedAt: new Date()
  });

  await wallet.save();

  await bot.sendMessage(chatId, `🔐 Premium forensics saved for Case #${wallet.caseNumber}.`);
});

// /premium_help — show admin the exact input format
bot.onText(/\/premium_help/, async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  await bot.sendMessage(chatId, PREMIUM_HELP_TEXT);
});

// /edit_premium [caseNumber|walletAddress] — edit premium forensic data on a verified report
bot.onText(/\/edit_premium(?:\s+(.+))?/, async (msg, match) => {
  if (String(msg.chat.id) !== String(chatId)) return;

  const query = match[1]?.trim();
  if (!query) {
    await bot.sendMessage(
      chatId,
      'Usage: /edit_premium [caseNumber] or [walletAddress]\n\nExample:\n  /edit_premium 42\n  /edit_premium So11111111111111111111111111111111111111112'
    );
    return;
  }

  let wallet;
  if (/^\d+$/.test(query)) {
    wallet = await Wallet.findOne({ caseNumber: parseInt(query, 10), status: 'verified' }).select('+premiumForensics');
  } else if (WALLET_ADDRESS_REGEX.test(query)) {
    wallet = await Wallet.findOne({ walletAddress: query, status: 'verified' }).select('+premiumForensics');
  } else {
    await bot.sendMessage(chatId, '❌ Invalid input. Provide a numeric case number or a valid Solana wallet address.');
    return;
  }

  if (!wallet) {
    await bot.sendMessage(chatId, '❌ No verified wallet found for that case number or address.');
    return;
  }

  const currentData = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
  const text        = buildEditCurrentValues(wallet.caseNumber, wallet.walletAddress, currentData);

  await bot.sendMessage(chatId, text, {
    reply_markup: {
      inline_keyboard: [
        [
          { text: '✏️ ADD_LIQ', callback_data: `editfield_addLiquidityValue_${wallet._id}` },
          { text: '✏️ REM_LIQ', callback_data: `editfield_removeLiquidityValue_${wallet._id}` }
        ],
        [
          { text: '✏️ FUNDING', callback_data: `editfield_walletFunding_${wallet._id}` },
          { text: '✏️ TOKENS',  callback_data: `editfield_tokensCreated_${wallet._id}` }
        ],
        [
          { text: '✏️ NOTES',  callback_data: `editfield_forensicNotes_${wallet._id}` },
          { text: '✏️ LINKS',  callback_data: `editfield_crossProjectLinks_${wallet._id}` }
        ]
      ]
    }
  });
});

// STEP 2c: Handle structured ADD_LIQ/REM_LIQ format input after [📝 Add Premium Data]
bot.on('message', async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  if (!msg.text) return;

  // Only process when admin has an active pending premium entry for this chat
  const pending = pendingPremiumEntry.get(String(msg.chat.id));
  if (!pending) return;

  // Check the message contains at least one recognised premium format key
  const hasFormatKey = Object.keys(PREMIUM_INPUT_KEYS).some(k => msg.text.includes(k + ':'));
  if (!hasFormatKey) return;

  const parsed = parsePremiumInput(msg.text);

  // Validate parsed fields (same rules as PATCH endpoint)
  const errors = validatePremiumFields(parsed);
  if (errors.length > 0) {
    await bot.sendMessage(
      chatId,
      `❌ Validation failed for Case #${pending.caseNumber}:\n\n${errors.map(e => `• ${e}`).join('\n')}\n\nPlease correct the format and try again. Use /premium_help for guidance.`
    );
    return;
  }

  // Store parsed data under a short random key, then ask for confirmation
  const confirmKey = crypto.randomBytes(8).toString('hex');
  pendingPremiumData.set(confirmKey, {
    walletId:      pending.walletId,
    walletAddress: pending.walletAddress,
    caseNumber:    pending.caseNumber,
    parsed
  });
  // Auto-expire confirmation after 5 minutes
  setTimeout(() => pendingPremiumData.delete(confirmKey), 5 * 60 * 1000);

  // Clear the pending entry (and its auto-expiry timer) — admin is now in the confirmation step
  clearTimeout(pending.timeoutId);
  pendingPremiumEntry.delete(String(msg.chat.id));

  const preview = buildPremiumPreview(pending.caseNumber, pending.walletAddress, parsed);
  await bot.sendMessage(chatId, preview, {
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Confirm', callback_data: `confirmpremium_${confirmKey}` },
        { text: '❌ Cancel',  callback_data: `cancelpremium_${confirmKey}` }
      ]]
    }
  });
});

// /canceledit command — cancel an active field-edit prompt
bot.onText(/\/canceledit/, async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  const pending = pendingFieldEdit.get(String(msg.chat.id));
  if (pending) {
    clearTimeout(pending.timeoutId);
    pendingFieldEdit.delete(String(msg.chat.id));
    await bot.sendMessage(chatId, '❌ Field edit cancelled.');
  } else {
    await bot.sendMessage(chatId, 'No active field edit to cancel.');
  }
});

// Handle new value entered for a specific field (when pendingFieldEdit is active)
bot.on('message', async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  if (!msg.text) return;

  // Ignore command messages
  if (msg.text.startsWith('/')) return;

  const pending = pendingFieldEdit.get(String(msg.chat.id));
  if (!pending) return;

  const { fieldName, oldValue, walletId, walletAddress, caseNumber, timeoutId } = pending;
  clearTimeout(timeoutId);
  pendingFieldEdit.delete(String(msg.chat.id));

  const fieldLabel = CAMEL_TO_KEY[fieldName] || fieldName;

  // Parse value: TOKENS and LINKS need to be split into arrays
  let newValue;
  if (fieldName === 'tokensCreated' || fieldName === 'crossProjectLinks') {
    newValue = msg.text.split(',').map(s => s.trim()).filter(Boolean);
  } else {
    newValue = msg.text.trim();
  }

  // Validate the single field using validatePremiumFields
  const errors = validatePremiumFields({ [fieldName]: newValue });
  if (errors.length > 0) {
    await bot.sendMessage(
      chatId,
      `❌ Invalid value for ${fieldLabel}:\n\n${errors.map(e => `• ${e}`).join('\n')}\n\nPlease use /edit_premium to try again. Use /premium_help for field rules.`
    );
    return;
  }

  const isSensitive = SENSITIVE_FIELDS.has(fieldName);
  const confirmKey  = crypto.randomBytes(8).toString('hex');
  pendingEditConfirm.set(confirmKey, {
    walletId,
    walletAddress,
    caseNumber,
    fieldName,
    oldValue,
    newValue
  });
  setTimeout(() => pendingEditConfirm.delete(confirmKey), 5 * 60 * 1000);

  const preview = buildDiffPreview(caseNumber, fieldLabel, oldValue, newValue, isSensitive);
  await bot.sendMessage(chatId, preview, {
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Confirm', callback_data: `confirmedit_${confirmKey}` },
        { text: '❌ Cancel',  callback_data: `canceledit_${confirmKey}` }
      ]]
    }
  });
});

// Handle NEW_VALUES: bulk replacement sent by admin during an edit session
bot.on('message', async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  if (!msg.text) return;

  if (!msg.text.startsWith('NEW_VALUES:')) return;

  // Fetch the most recently edited wallet by looking at pending edit session or last verified wallet
  // Since the admin uses /edit_premium to establish context, we look at whether they are in the
  // middle of a field edit or we need them to provide the case via /edit_premium first.
  // For NEW_VALUES we require the admin has just run /edit_premium (stored in pendingBulkEdit source).
  // We instead accept NEW_VALUES from any admin in the authorised chat and ask them to specify wallet.

  const content = msg.text.slice('NEW_VALUES:'.length).trim();
  if (!content) {
    await bot.sendMessage(
      chatId,
      '❌ No values provided after NEW_VALUES:.\n\nFormat:\nNEW_VALUES:\nADD_LIQ: 45.2 SOL\nFUNDING: Mixer (Tornado)'
    );
    return;
  }

  // NEW_VALUES requires an active edit session started by /edit_premium.
  // We look for any recently-active edit context stored in pendingFieldEdit,
  // or if the admin just finished one. To avoid ambiguity, require:
  //   NEW_VALUES: [caseNumber]\n<fields>  OR  NEW_VALUES: [walletAddress]\n<fields>
  const lines         = content.split('\n');
  const firstLine     = lines[0].trim();
  const fieldContent  = lines.slice(1).join('\n');

  let wallet;
  if (/^\d+$/.test(firstLine)) {
    wallet = await Wallet.findOne({ caseNumber: parseInt(firstLine, 10), status: 'verified' }).select('+premiumForensics');
  } else if (WALLET_ADDRESS_REGEX.test(firstLine)) {
    wallet = await Wallet.findOne({ walletAddress: firstLine, status: 'verified' }).select('+premiumForensics');
  } else {
    await bot.sendMessage(
      chatId,
      '❌ First line of NEW_VALUES: must be a case number or wallet address.\n\nFormat:\nNEW_VALUES: [caseNumber or walletAddress]\nADD_LIQ: 45.2 SOL\nFUNDING: Mixer (Tornado)'
    );
    return;
  }

  if (!wallet) {
    await bot.sendMessage(chatId, '❌ No verified wallet found for that identifier.');
    return;
  }

  if (!fieldContent.trim()) {
    await bot.sendMessage(chatId, '❌ No field values found after the case identifier. Use /premium_help for format.');
    return;
  }

  const parsed = parsePremiumInput(fieldContent);
  const errors = validatePremiumFields(parsed);
  if (errors.length > 0) {
    await bot.sendMessage(
      chatId,
      `❌ Validation failed:\n\n${errors.map(e => `• ${e}`).join('\n')}\n\nUse /premium_help for field format.`
    );
    return;
  }

  if (Object.keys(parsed).length === 0) {
    await bot.sendMessage(chatId, '❌ No recognised fields found. Use /premium_help for the correct format.');
    return;
  }

  const currentData = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
  const preview     = buildBulkDiffPreview(wallet.caseNumber, wallet.walletAddress, currentData, parsed);
  const confirmKey  = crypto.randomBytes(8).toString('hex');

  pendingBulkEdit.set(confirmKey, {
    walletId:      wallet._id,
    walletAddress: wallet.walletAddress,
    caseNumber:    wallet.caseNumber,
    currentData,
    parsed
  });
  setTimeout(() => pendingBulkEdit.delete(confirmKey), 5 * 60 * 1000);

  await bot.sendMessage(chatId, preview, {
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Confirm All', callback_data: `confirmbulkedit_${confirmKey}` },
        { text: '❌ Cancel',      callback_data: `cancelbulkedit_${confirmKey}` }
      ]]
    }
  });
});
bot.on('callback_query', async (query) => {
  // Verify the callback originates from an authorized admin chat and user
  if (!telegramAdminAuth(query)) {
    await bot.answerCallbackQuery(query.id, { text: '⛔ Unauthorized.' });
    return;
  }

  // Use first-underscore split so compound callback data (e.g. editfield_fieldName_walletId)
  // is correctly parsed regardless of underscores in later segments.
  const firstUnderscore = query.data.indexOf('_');
  const action = firstUnderscore >= 0 ? query.data.slice(0, firstUnderscore) : query.data;
  const id     = firstUnderscore >= 0 ? query.data.slice(firstUnderscore + 1) : '';

  if (action === 'review') {
    const wallet = await Wallet.findById(id);
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    await bot.answerCallbackQuery(query.id, { text: 'Loading details…' });
    await bot.sendMessage(
      chatId,
      `🔍 Case #${wallet.caseNumber}\n\n` +
      `📍 Address: ${wallet.walletAddress}\n` +
      `📊 Status: ${wallet.status}\n` +
      `⚠️ Risk Score: ${wallet.riskScore ?? 'N/A'}\n` +
      `📝 Description: ${wallet.evidence?.description || '(none)'}\n` +
      `🔗 Tx Hash: ${wallet.evidence?.txHash || '(none)'}\n` +
      `🗂 Reports: ${wallet.reportCount ?? 1}`
    );
    return;
  }

  if (action === 'reject') {
    const wallet = await Wallet.findById(id);
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    wallet.status = 'rejected';
    await wallet.save();
    await bot.answerCallbackQuery(query.id, { text: '❌ Case rejected.' });
    await bot.sendMessage(chatId, `❌ Case #${wallet.caseNumber} has been rejected.`);
    return;
  }

  if (action === 'addpremium') {
    const wallet = await Wallet.findById(id);
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    // Store pending entry so the next matching message is attributed to this wallet
    const timeoutId = setTimeout(
      () => pendingPremiumEntry.delete(String(chatId)),
      10 * 60 * 1000
    );
    pendingPremiumEntry.set(String(chatId), {
      walletId:      wallet._id,
      walletAddress: wallet.walletAddress,
      caseNumber:    wallet.caseNumber,
      timeoutId
    });
    await bot.answerCallbackQuery(query.id, { text: 'Send premium data now.' });
    await bot.sendMessage(
      chatId,
      `📝 Enter premium forensic data for Case #${wallet.caseNumber} in the format:\n\n` +
      `ADD_LIQ: 45.2 SOL\n` +
      `REM_LIQ: 0.3 SOL\n` +
      `FUNDING: CEX withdrawal (Binance)\n` +
      `TOKENS: Token1Addr,Token2Addr\n` +
      `NOTES: Repeated rugpull pattern across 3 projects\n` +
      `LINKS: RelatedWallet1,RelatedWallet2\n\n` +
      `Use /premium_help for field rules.`
    );
    return;
  }

  if (action === 'confirmpremium') {
    const pendingData = pendingPremiumData.get(id);
    if (!pendingData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Please click [📝 Add Premium Data] again.'
      });
    }
    pendingPremiumData.delete(id);

    const wallet = await Wallet.findById(pendingData.walletId).select('+premiumForensics');
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }

    const { parsed } = pendingData;
    const existing = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
    const update = { updatedAt: new Date() };
    const fieldsChanged = [];
    const before = {};
    const after  = {};

    if (parsed.addLiquidityValue !== undefined)   { before.addLiquidityValue   = existing.addLiquidityValue   ?? null; after.addLiquidityValue   = parsed.addLiquidityValue;   update.addLiquidityValue   = parsed.addLiquidityValue;   fieldsChanged.push('addLiquidityValue'); }
    if (parsed.removeLiquidityValue !== undefined) { before.removeLiquidityValue = existing.removeLiquidityValue ?? null; after.removeLiquidityValue = parsed.removeLiquidityValue; update.removeLiquidityValue = parsed.removeLiquidityValue; fieldsChanged.push('removeLiquidityValue'); }
    if (parsed.walletFunding !== undefined)        { before.walletFunding        = existing.walletFunding        ?? null; after.walletFunding        = parsed.walletFunding;        update.walletFunding        = parsed.walletFunding;        fieldsChanged.push('walletFunding'); }
    if (parsed.tokensCreated !== undefined)        { before.tokensCreated        = existing.tokensCreated        ?? [];   after.tokensCreated        = parsed.tokensCreated;        update.tokensCreated        = parsed.tokensCreated;        fieldsChanged.push('tokensCreated'); }
    if (parsed.forensicNotes !== undefined)        { before.forensicNotes        = existing.forensicNotes        ?? null; after.forensicNotes        = parsed.forensicNotes;        update.forensicNotes        = parsed.forensicNotes;        fieldsChanged.push('forensicNotes'); }
    if (parsed.crossProjectLinks !== undefined)    { before.crossProjectLinks    = existing.crossProjectLinks    ?? [];   after.crossProjectLinks    = parsed.crossProjectLinks;    update.crossProjectLinks    = parsed.crossProjectLinks;    fieldsChanged.push('crossProjectLinks'); }

    wallet.set('premiumForensics', Object.assign({}, existing, update));
    await wallet.save();

    writeAuditLog({
      timestamp:  new Date().toISOString(),
      action:     'premium_update',
      walletAddress: wallet.walletAddress,
      caseNumber: wallet.caseNumber,
      changedBy:  { source: 'telegram', identifier: `chat.id:${query.from.id}` },
      fieldsChanged,
      before,
      after
    });

    await bot.answerCallbackQuery(query.id, { text: '✅ Saved!' });
    await bot.sendMessage(
      chatId,
      `✅ Premium forensics saved for Case #${wallet.caseNumber}.\nFields updated: ${fieldsChanged.join(', ') || 'none'}`
    );
    return;
  }

  if (action === 'cancelpremium') {
    pendingPremiumData.delete(id);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Premium data entry cancelled.');
    return;
  }

  if (action === 'verify') {
    const wallet = await Wallet.findById(id);

    if (!wallet.forensic?.liquidityBefore) {
      return bot.answerCallbackQuery(query.id, {
        text: 'Isi forensic dulu!'
      });
    }

    wallet.status = 'verified';
    await wallet.save();

    await bot.sendMessage(chatId,
      `✅ Case #${wallet.caseNumber} Verified\nRisk Score: ${wallet.riskScore}`,
      {
        reply_markup: {
          inline_keyboard: [[
            { text: '🔐 Set Premium Forensics', callback_data: `setpremium_${wallet._id}` }
          ]]
        }
      }
    );
  }

  if (action === 'setpremium') {
    const wallet = await Wallet.findById(id);
    if (!wallet) return;

    await bot.answerCallbackQuery(query.id, { text: 'Kirim data premium forensic.' });
    await bot.sendMessage(chatId,
      `📋 Case #${wallet.caseNumber} — Premium Forensics\n\nKirim dengan format:\n\nAddLiquidityValue:\nRemoveLiquidityValue:\nWalletFunding:\nTokensCreated:\nForensicNotes:\nCrossProjectLinks:\nWalletId: ${wallet._id}`
    );
  }

  // ── editfield: admin clicked ✏️ next to a specific field ─────────────────
  if (action === 'editfield') {
    // id = '<fieldName>_<walletId>'  (neither camelCase nor MongoDB ObjectId contain underscores)
    const sepIdx    = id.indexOf('_');
    const fieldName = id.slice(0, sepIdx);
    const walletId  = id.slice(sepIdx + 1);

    const wallet = await Wallet.findById(walletId).select('+premiumForensics');
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    if (wallet.status !== 'verified') {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet is not verified.' });
    }

    const currentData = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
    const oldValue    = currentData[fieldName];
    const fieldLabel  = CAMEL_TO_KEY[fieldName] || fieldName;

    const fmt = (val) => {
      if (val === undefined || val === null) return '(not set)';
      return Array.isArray(val) ? val.join(', ') : String(val);
    };

    const timeoutId = setTimeout(
      () => pendingFieldEdit.delete(String(chatId)),
      10 * 60 * 1000
    );
    pendingFieldEdit.set(String(chatId), {
      walletId:      wallet._id,
      walletAddress: wallet.walletAddress,
      caseNumber:    wallet.caseNumber,
      fieldName,
      oldValue,
      timeoutId
    });

    await bot.answerCallbackQuery(query.id, { text: `Editing ${fieldLabel}…` });
    await bot.sendMessage(
      chatId,
      `✏️ Enter new value for ${fieldLabel} (Case #${wallet.caseNumber}):\n\nCurrent: ${fmt(oldValue)}\n\nFor TOKENS and LINKS, send comma-separated Base58 addresses.\nSend /canceledit to cancel.`
    );
    return;
  }

  // ── confirmedit: admin confirmed a single-field diff ──────────────────────
  if (action === 'confirmedit') {
    const confirmData = pendingEditConfirm.get(id);
    if (!confirmData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Use /edit_premium to start again.'
      });
    }
    pendingEditConfirm.delete(id);

    if (!checkAdminEditRateLimit(String(chatId))) {
      await bot.answerCallbackQuery(query.id, { text: '🚫 Rate limit reached.' });
      await bot.sendMessage(chatId, `🚫 Rate limit reached: max ${EDIT_RATE_LIMIT} edits per hour per admin. Please wait before making more changes.`);
      return;
    }

    const wallet = await Wallet.findById(confirmData.walletId).select('+premiumForensics');
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    if (wallet.status !== 'verified') {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet is no longer verified.' });
    }

    const beforeValues = {};
    const afterValues  = {};
    const update       = { updatedAt: new Date() };

    beforeValues[confirmData.fieldName] = confirmData.oldValue;
    afterValues[confirmData.fieldName]  = confirmData.newValue;
    update[confirmData.fieldName]       = confirmData.newValue;

    wallet.set('premiumForensics', Object.assign(
      wallet.premiumForensics ? wallet.premiumForensics.toObject() : {},
      update
    ));
    await wallet.save();

    writeAuditLog({
      timestamp:     new Date().toISOString(),
      action:        'premium_update',
      walletAddress: wallet.walletAddress,
      caseNumber:    wallet.caseNumber,
      changedBy:     { source: 'telegram', identifier: `chat.id:${query.from.id}` },
      fieldsChanged: [confirmData.fieldName],
      before:        beforeValues,
      after:         afterValues
    });

    await bot.answerCallbackQuery(query.id, { text: '✅ Updated!' });
    await bot.sendMessage(
      chatId,
      `✅ ${CAMEL_TO_KEY[confirmData.fieldName] || confirmData.fieldName} updated for Case #${wallet.caseNumber}.`
    );
    return;
  }

  // ── canceledit: admin cancelled a single-field diff ───────────────────────
  if (action === 'canceledit') {
    pendingEditConfirm.delete(id);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Field edit cancelled.');
    return;
  }

  // ── confirmbulkedit: admin confirmed a bulk (NEW_VALUES) update ───────────
  if (action === 'confirmbulkedit') {
    const bulkData = pendingBulkEdit.get(id);
    if (!bulkData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Use /edit_premium and send NEW_VALUES: ... again.'
      });
    }
    pendingBulkEdit.delete(id);

    if (!checkAdminEditRateLimit(String(chatId))) {
      await bot.answerCallbackQuery(query.id, { text: '🚫 Rate limit reached.' });
      await bot.sendMessage(chatId, `🚫 Rate limit reached: max ${EDIT_RATE_LIMIT} edits per hour per admin.`);
      return;
    }

    const wallet = await Wallet.findById(bulkData.walletId).select('+premiumForensics');
    if (!wallet) {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    }
    if (wallet.status !== 'verified') {
      return bot.answerCallbackQuery(query.id, { text: '❌ Wallet is no longer verified.' });
    }

    const { parsed, currentData } = bulkData;
    const update        = { updatedAt: new Date() };
    const fieldsChanged = [];
    const beforeValues  = {};
    const afterValues   = {};

    for (const camelField of Object.keys(CAMEL_TO_KEY)) {
      if (parsed[camelField] !== undefined) {
        update[camelField]       = parsed[camelField];
        beforeValues[camelField] = currentData[camelField];
        afterValues[camelField]  = parsed[camelField];
        fieldsChanged.push(camelField);
      }
    }

    wallet.set('premiumForensics', Object.assign(
      wallet.premiumForensics ? wallet.premiumForensics.toObject() : {},
      update
    ));
    await wallet.save();

    writeAuditLog({
      timestamp:     new Date().toISOString(),
      action:        'premium_update',
      walletAddress: wallet.walletAddress,
      caseNumber:    wallet.caseNumber,
      changedBy:     { source: 'telegram', identifier: `chat.id:${query.from.id}` },
      fieldsChanged,
      before:        beforeValues,
      after:         afterValues
    });

    await bot.answerCallbackQuery(query.id, { text: '✅ Saved!' });
    await bot.sendMessage(
      chatId,
      `✅ Bulk premium update saved for Case #${wallet.caseNumber}.\nFields updated: ${fieldsChanged.join(', ') || 'none'}`
    );
    return;
  }

  // ── cancelbulkedit: admin cancelled a bulk (NEW_VALUES) update ───────────
  if (action === 'cancelbulkedit') {
    pendingBulkEdit.delete(id);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Bulk edit cancelled.');
    return;
  }
});

/**
 * ==========================
 * ROUTES
 * ==========================
 */

// PUBLIC LIST
app.get('/api/wallets', async (req, res) => {
  try {
    const wallets = await Wallet.find({ status: 'verified' })
      .select('-forensic -premiumForensics -__v');
    res.json(wallets.map(w => formatWalletResponse(w)));
  } catch (err) {
    console.error('GET /api/wallets error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PUBLIC DETAIL
// Accepts optional ?include=premium query param.
// When ?include=premium is present, requireAccess('premium') is applied and
// the response includes forensic + premiumForensics fields.
function premiumQueryGate(req, res, next) {
  if (req.query.include === 'premium') {
    return requireAccess('premium', { amountUSD: 0.11 })(req, res, next);
  }
  return requireAccess('public')(req, res, next);
}

app.get('/api/wallets/:address', premiumQueryGate, async (req, res) => {
  try {
    const hasPremiumAccess = req.hasPremiumAccess === true;
    const selectFields = hasPremiumAccess
      ? '-forensic -__v +premiumForensics'
      : '-forensic -__v';

    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      status: 'verified'
    }).select(selectFields);

    if (!wallet) return res.status(404).json({ message: 'Not found' });

    res.json(formatWalletResponse(wallet, { hasPremiumAccess }));
  } catch (err) {
    console.error('GET /api/wallets/:address error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// EXPLICIT PREMIUM UNLOCK ENDPOINT (x402 payment required)
// POST /api/wallets/:address/premium/access
// Returns forensic + premiumForensics for verified wallets after payment.
app.post('/api/wallets/:address/premium/access', verifyX402Payment(0.11), async (req, res) => {
  try {
    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      status: 'verified'
    }).select('+premiumForensics');

    if (!wallet) return res.status(404).json({ message: 'Not found' });

    res.json({
      payerAddress:    req.x402.payerAddress,
      forensic:        wallet.forensic        || null,
      premiumForensics: wallet.premiumForensics || null
    });
  } catch (err) {
    console.error('POST /api/wallets/:address/premium/access error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// SUBMIT REPORT
const WALLET_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TX_HASH_REGEX = /^[1-9A-HJ-NP-Za-km-z]{1,100}$/;

app.post('/api/wallets', submitRateLimit, async (req, res) => {
  try {
    // Only destructure known fields — reporterContact is intentionally excluded to avoid PII storage
    const { walletAddress, evidence, tokenAddress } = req.body;

    // Validate wallet address (Solana base58, 32–44 chars)
    if (!walletAddress || !WALLET_ADDRESS_REGEX.test(walletAddress)) {
      return res.status(400).json({ success: false, message: 'Invalid wallet address format.' });
    }

    // Validate optional token address
    if (tokenAddress && !WALLET_ADDRESS_REGEX.test(tokenAddress)) {
      return res.status(400).json({ success: false, message: 'Invalid token address format.' });
    }

    // Validate description
    const description = typeof evidence?.description === 'string' ? evidence.description.trim() : '';
    if (description.length > 500) {
      return res.status(400).json({ success: false, message: 'Description must be 500 characters or fewer.' });
    }

    // Validate projectName
    const projectName = typeof req.body.projectName === 'string' ? req.body.projectName.trim() : '';
    if (projectName.length > 100) {
      return res.status(400).json({ success: false, message: 'Project name must be 100 characters or fewer.' });
    }

    // Validate txHash (base58, max 100 chars)
    const txHash = typeof evidence?.txHash === 'string' ? evidence.txHash.trim() : '';
    if (txHash && !TX_HASH_REGEX.test(txHash)) {
      return res.status(400).json({ success: false, message: 'Invalid transaction hash format.' });
    }

    // If wallet already exists, increment report count
    const existing = await Wallet.findOne({ walletAddress });
    if (existing) {
      existing.reportCount = (existing.reportCount || 0) + 1;
      await existing.save();
      return res.json({ success: true, message: 'Report added to existing case', data: { caseNumber: existing.caseNumber } });
    }

    // Create new wallet record
    const wallet = new Wallet({
      walletAddress,
      evidence: {
        txHash: txHash || undefined,
        description: description || undefined
      },
      projectName: projectName || undefined,
      tokenAddress: tokenAddress || undefined
    });

    await wallet.save();

    // Notify admin via Telegram
    await requestForensicInput(wallet);

    return res.status(201).json({ success: true, message: 'Report submitted', data: { caseNumber: wallet.caseNumber } });
  } catch (err) {
    console.error('POST /api/wallets error:', err.message);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

/**
 * PREMIUM ENDPOINT (x402 REQUIRED)
 * Uses basic mode (timingSafeEqual against X402_PAYMENT_SECRET) for
 * backward compatibility with existing payment integrations.
 */
app.get('/api/wallets/:address/premium', verifyX402Payment({ mode: 'basic' }), async (req, res) => {
  try {
    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      status: 'verified'
    }).select('+premiumForensics');

    if (!wallet) return res.status(404).json({ message: 'Not found' });

    res.json({
      forensic: wallet.forensic || null,
      premiumForensics: wallet.premiumForensics || null
    });
  } catch (err) {
    console.error('GET /api/wallets/:address/premium error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * ADMIN ENDPOINT — Update premiumForensics (X-Admin-Token required)
 */
app.post('/api/admin/wallets/:address/premium-forensics', async (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  const validAdminToken = process.env.ADMIN_SECRET;

  if (!adminToken || !validAdminToken) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  try {
    const tokenBuf = Buffer.from(adminToken);
    const validBuf = Buffer.from(validAdminToken);
    if (tokenBuf.length !== validBuf.length || !crypto.timingSafeEqual(tokenBuf, validBuf)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
  } catch {
    return res.status(403).json({ message: 'Forbidden' });
  }

  try {
    const wallet = await Wallet.findOne({ walletAddress: req.params.address }).select('+premiumForensics');
    if (!wallet) return res.status(404).json({ message: 'Not found' });

    const {
      addLiquidityValue,
      removeLiquidityValue,
      walletFunding,
      tokensCreated,
      forensicNotes,
      crossProjectLinks
    } = req.body;

    const update = { updatedAt: new Date() };
    if (addLiquidityValue !== undefined) update.addLiquidityValue = String(addLiquidityValue);
    if (removeLiquidityValue !== undefined) update.removeLiquidityValue = String(removeLiquidityValue);
    if (walletFunding !== undefined) update.walletFunding = String(walletFunding);
    if (Array.isArray(tokensCreated)) update.tokensCreated = tokensCreated.map(String);
    if (forensicNotes !== undefined) update.forensicNotes = String(forensicNotes);
    if (Array.isArray(crossProjectLinks)) update.crossProjectLinks = crossProjectLinks.map(String);

    wallet.set('premiumForensics', Object.assign(
      wallet.premiumForensics ? wallet.premiumForensics.toObject() : {},
      update
    ));
    await wallet.save();

    res.json({ success: true, premiumForensics: wallet.premiumForensics });
  } catch (err) {
    console.error('POST /api/admin/wallets/:address/premium-forensics error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * ADMIN PATCH ENDPOINT — Partial update of premiumForensics
 * Authorization: EITHER Telegram admin token OR x402-payment JWT (admin wallet whitelist).
 * Rate limited: 20 updates per hour per admin token.
 */
app.patch('/api/admin/wallets/:address/premium', adminPremiumRateLimit, requireAccess('admin', { adminSources: ['telegram', 'jwt'] }), async (req, res) => {
  // ── Destructure only the 6 allowed premiumForensics fields ─────────────────
  const {
    addLiquidityValue,
    removeLiquidityValue,
    walletFunding,
    tokensCreated,
    forensicNotes,
    crossProjectLinks
  } = req.body;

  // ── Validation ─────────────────────────────────────────────────────────────
  const errors = [];

  if (addLiquidityValue !== undefined) {
    if (typeof addLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(addLiquidityValue)) {
      errors.push('addLiquidityValue must match /^\\d+(\\.\\d+)?\\s*(SOL|USDC|USD)?$/i');
    }
  }

  if (removeLiquidityValue !== undefined) {
    if (typeof removeLiquidityValue !== 'string' || !LIQUIDITY_VALUE_REGEX.test(removeLiquidityValue)) {
      errors.push('removeLiquidityValue must match /^\\d+(\\.\\d+)?\\s*(SOL|USDC|USD)?$/i');
    }
  }

  if (walletFunding !== undefined) {
    if (
      typeof walletFunding !== 'string' ||
      walletFunding.length > 200 ||
      HTML_TAG_REGEX.test(walletFunding)
    ) {
      errors.push('walletFunding must be a string, max 200 chars, with no HTML tags');
    }
  }

  if (tokensCreated !== undefined) {
    if (
      !Array.isArray(tokensCreated) ||
      !tokensCreated.every(addr => typeof addr === 'string' && WALLET_ADDRESS_REGEX.test(addr))
    ) {
      errors.push('tokensCreated must be an array of valid Solana Base58 addresses (32–44 chars)');
    }
  }

  if (forensicNotes !== undefined) {
    if (typeof forensicNotes !== 'string' || HTML_TAG_REGEX.test(forensicNotes)) {
      errors.push('forensicNotes must be a string with no HTML tags');
    }
  }

  if (crossProjectLinks !== undefined) {
    if (
      !Array.isArray(crossProjectLinks) ||
      !crossProjectLinks.every(addr => typeof addr === 'string' && WALLET_ADDRESS_REGEX.test(addr))
    ) {
      errors.push('crossProjectLinks must be an array of valid Solana Base58 addresses (32–44 chars)');
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({ success: false, message: 'Validation failed', errors });
  }

  // ── Persist update ─────────────────────────────────────────────────────────
  try {
    const wallet = await Wallet.findOne({ walletAddress: req.params.address }).select('+premiumForensics');
    if (!wallet) return res.status(404).json({ success: false, message: 'Not found' });

    const existing = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
    const fieldsChanged = [];
    const update = { updatedAt: new Date() };
    const before = {};
    const after  = {};

    if (addLiquidityValue !== undefined)   { before.addLiquidityValue   = existing.addLiquidityValue   ?? null; after.addLiquidityValue   = addLiquidityValue;   update.addLiquidityValue   = addLiquidityValue;   fieldsChanged.push('addLiquidityValue'); }
    if (removeLiquidityValue !== undefined) { before.removeLiquidityValue = existing.removeLiquidityValue ?? null; after.removeLiquidityValue = removeLiquidityValue; update.removeLiquidityValue = removeLiquidityValue; fieldsChanged.push('removeLiquidityValue'); }
    if (walletFunding !== undefined)        { before.walletFunding        = existing.walletFunding        ?? null; after.walletFunding        = walletFunding;        update.walletFunding        = walletFunding;        fieldsChanged.push('walletFunding'); }
    if (tokensCreated !== undefined)        { before.tokensCreated        = existing.tokensCreated        ?? [];   after.tokensCreated        = tokensCreated;        update.tokensCreated        = tokensCreated;        fieldsChanged.push('tokensCreated'); }
    if (forensicNotes !== undefined)        { before.forensicNotes        = existing.forensicNotes        ?? null; after.forensicNotes        = forensicNotes;        update.forensicNotes        = forensicNotes;        fieldsChanged.push('forensicNotes'); }
    if (crossProjectLinks !== undefined)    { before.crossProjectLinks    = existing.crossProjectLinks    ?? [];   after.crossProjectLinks    = crossProjectLinks;    update.crossProjectLinks    = crossProjectLinks;    fieldsChanged.push('crossProjectLinks'); }

    wallet.set('premiumForensics', Object.assign({}, existing, update));
    await wallet.save();

    const timestamp = new Date().toISOString();
    const changedBySource     = req.adminAuth.source;
    const changedByIdentifier = req.adminAuth.payerAddress
      ? `wallet:${req.adminAuth.payerAddress}`
      : `${req.adminAuth.source}-admin`;
    writeAuditLog({
      timestamp,
      action:        'premium_update',
      walletAddress: req.params.address,
      caseNumber:    wallet.caseNumber,
      changedBy:     { source: changedBySource, identifier: changedByIdentifier },
      fieldsChanged,
      before,
      after,
      ipHash:        hashIp(req.ip)
    });

    return res.json({
      success: true,
      wallet: formatWalletResponse(wallet, { hasPremiumAccess: true }),
      auditLog: {
        updatedBy: 'admin',
        timestamp,
        fieldsChanged
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ── GET /api/admin/audit — return last 50 audit entries for a wallet ──────────
app.get('/api/admin/audit', requireAdminAuth('api'), (req, res) => {
  const { wallet } = req.query;

  if (!wallet || !WALLET_ADDRESS_REGEX.test(wallet)) {
    return res.status(400).json({ success: false, message: 'Invalid or missing wallet query parameter' });
  }

  try {
    let content;
    try {
      content = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
    } catch (readErr) {
      if (readErr.code === 'ENOENT') return res.json({ success: true, entries: [] });
      throw readErr;
    }

    const entries = content
      .split('\n')
      .filter(Boolean)
      .map(line => {
        try { return JSON.parse(line); } catch (e) {
          process.stderr.write(`[audit] invalid JSON line skipped: ${e.message}\n`);
          return null;
        }
      })
      .filter(entry => entry !== null && entry.walletAddress === wallet)
      .slice(-50);

    return res.json({ success: true, entries });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`);
  if (!process.env.X402_PAYMENT_SECRET) {
    console.warn('WARNING: X402_PAYMENT_SECRET is not set. The premium endpoint will reject all requests.');
  }
});

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
const workflowState = require('./utils/workflowState');
const {
  parsePremiumInput,
  validatePremiumFields,
  buildPremiumPreview,
  buildDeletePreview,
  PREMIUM_HELP_TEXT,
  PREMIUM_INPUT_KEYS,
  CAMEL_TO_KEY,
  SENSITIVE_FIELDS,
  buildEditCurrentValues,
  buildDiffPreview,
  buildBulkDiffPreview,
  CALLBACK
} = require('./botUtils');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());

// Support comma-separated origins in ALLOWED_ORIGIN env var, e.g.:
//   ALLOWED_ORIGIN=https://suspected.dev,https://www.suspected.dev
// Requests with no Origin header (curl, Postman, server-to-server) are always allowed.
const allowedOrigins = (process.env.ALLOWED_ORIGIN || 'https://suspected.dev')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

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
    console.error('MongoDB initial connection error:', err.message);
  });

mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.warn('MongoDB disconnected — attempting automatic reconnect');
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
// Stores delete confirmations awaiting admin approval: confirmKey → { walletId, walletAddress, caseNumber, premiumSnapshot }
const pendingDelete = new Map();

// Per-admin edit rate limiter: chatId → { count, windowStart }
const adminEditRateLimiter = new Map();
const EDIT_RATE_LIMIT     = 5;
const EDIT_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour

// Ordered sequence of fields for the multi-step premium_add workflow
const PREMIUM_WORKFLOW_FIELDS = [
  'addLiquidityValue',
  'removeLiquidityValue',
  'walletFunding',
  'tokensCreated',
  'forensicNotes',
  'crossProjectLinks'
];

// Fields whose values are comma-separated lists → parsed as arrays
const ARRAY_PREMIUM_FIELDS = new Set(['tokensCreated', 'crossProjectLinks']);

// Step-by-step prompt shown to the admin for each field
const WORKFLOW_FIELD_PROMPTS = {
  addLiquidityValue:    'Step 1/6 — ADD_LIQ\nEnter add-liquidity value (e.g. 45.2 SOL).\nSend /skip to leave blank.',
  removeLiquidityValue: 'Step 2/6 — REM_LIQ\nEnter remove-liquidity value (e.g. 0.3 SOL).\nSend /skip to leave blank.',
  walletFunding:        'Step 3/6 — FUNDING\nEnter wallet funding source (plain text, max 200 chars, no HTML).\nSend /skip to leave blank.',
  tokensCreated:        'Step 4/6 — TOKENS\nEnter token addresses as comma-separated Solana Base58 values.\nSend /skip to leave blank.',
  forensicNotes:        'Step 5/6 — NOTES\nEnter free-form forensic notes.\nSend /skip to leave blank.',
  crossProjectLinks:    'Step 6/6 — LINKS\nEnter related wallet addresses as comma-separated Solana Base58 values.\nSend /skip to leave blank.'
};

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
            { text: '🔍 Review',           callback_data: `review:${wallet._id}` },
            { text: '✅ Verify',           callback_data: `verify:${wallet._id}` }
          ],
          [
            { text: '❌ Reject',           callback_data: `reject:${wallet._id}` },
            { text: '📝 Add Premium Data', callback_data: `premium:add:${wallet._id}` }
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

  if (!msg.text || !msg.text.includes('LiquidityBefore')) return;

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
          { text: '✅ Verify', callback_data: `verify:${wallet._id}` }
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
          { text: '✏️ ADD_LIQ', callback_data: `premium:edit:addLiquidityValue:${wallet._id}` },
          { text: '✏️ REM_LIQ', callback_data: `premium:edit:removeLiquidityValue:${wallet._id}` }
        ],
        [
          { text: '✏️ FUNDING', callback_data: `premium:edit:walletFunding:${wallet._id}` },
          { text: '✏️ TOKENS',  callback_data: `premium:edit:tokensCreated:${wallet._id}` }
        ],
        [
          { text: '✏️ NOTES',  callback_data: `premium:edit:forensicNotes:${wallet._id}` },
          { text: '✏️ LINKS',  callback_data: `premium:edit:crossProjectLinks:${wallet._id}` }
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
        { text: '✅ Confirm', callback_data: `premium:confirm:add:${confirmKey}` },
        { text: '❌ Cancel',  callback_data: `cancel:add:${confirmKey}` }
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

/**
 * Look up a verified wallet by case number or Solana address.
 *
 * @param {string}  query          Raw admin input (numeric case number or address).
 * @param {boolean} [withPremium]  When true, includes the premiumForensics subdocument.
 * @returns {Promise<{wallet: object|null, error: string|null}>}
 *   wallet is null when not found or input is invalid; error contains a
 *   user-facing error message in that case (null when wallet was found).
 */
async function lookupVerifiedWallet(query, withPremium = false) {
  const selectStr = withPremium ? '+premiumForensics' : undefined;

  if (/^\d+$/.test(query)) {
    const wallet = await (selectStr
      ? Wallet.findOne({ caseNumber: parseInt(query, 10), status: 'verified' }).select(selectStr)
      : Wallet.findOne({ caseNumber: parseInt(query, 10), status: 'verified' }));
    if (!wallet) return { wallet: null, error: '❌ No verified wallet found for that case number or address.' };
    return { wallet, error: null };
  }

  if (WALLET_ADDRESS_REGEX.test(query)) {
    const wallet = await (selectStr
      ? Wallet.findOne({ walletAddress: query, status: 'verified' }).select(selectStr)
      : Wallet.findOne({ walletAddress: query, status: 'verified' }));
    if (!wallet) return { wallet: null, error: '❌ No verified wallet found for that case number or address.' };
    return { wallet, error: null };
  }

  return { wallet: null, error: '❌ Invalid input. Provide a numeric case number or a valid Solana wallet address.' };
}

// /add_premium [caseNumber|walletAddress] — proactively start a premium data add workflow
bot.onText(/\/add_premium(?:\s+(.+))?/, async (msg, match) => {
  if (String(msg.chat.id) !== String(chatId)) return;

  const query = match[1]?.trim();
  if (!query) {
    await bot.sendMessage(
      chatId,
      'Usage: /add_premium [caseNumber] or [walletAddress]\n\nExample:\n  /add_premium 42\n  /add_premium So11111111111111111111111111111111111111112'
    );
    return;
  }

  const { wallet, error } = await lookupVerifiedWallet(query, false);
  if (error) {
    await bot.sendMessage(chatId, error);
    return;
  }

  const adminChatId = String(msg.chat.id);

  // Guard: abort if a workflow is already in progress for this chat
  const existing = workflowState.get(adminChatId);
  if (existing) {
    await bot.sendMessage(
      chatId,
      `⚠️ You already have an active premium data entry in progress (Case #${existing.caseNumber}).\n\n` +
      `Send /cancel to discard it, then try again.`
    );
    return;
  }

  workflowState.set(adminChatId, {
    workflow:      'premium_add',
    walletId:      wallet._id,
    walletAddress: wallet.walletAddress,
    caseNumber:    wallet.caseNumber,
    currentField:  PREMIUM_WORKFLOW_FIELDS[0],
    collectedData: {}
  });

  await bot.sendMessage(
    chatId,
    `📝 Premium data entry for Case #${wallet.caseNumber}\n(${wallet.walletAddress})\n\n` +
    `Answer each prompt in sequence.\nSend /skip to leave a field blank.\nSend /cancel to abort.\n\n` +
    WORKFLOW_FIELD_PROMPTS[PREMIUM_WORKFLOW_FIELDS[0]]
  );
});

// /delete_premium [caseNumber|walletAddress] — delete all premium forensic data from a wallet
bot.onText(/\/delete_premium(?:\s+(.+))?/, async (msg, match) => {
  if (String(msg.chat.id) !== String(chatId)) return;

  const query = match[1]?.trim();
  if (!query) {
    await bot.sendMessage(
      chatId,
      'Usage: /delete_premium [caseNumber] or [walletAddress]\n\nExample:\n  /delete_premium 42\n  /delete_premium So11111111111111111111111111111111111111112'
    );
    return;
  }

  const { wallet, error } = await lookupVerifiedWallet(query, true);
  if (error) {
    await bot.sendMessage(chatId, error);
    return;
  }

  const currentData = wallet.premiumForensics ? wallet.premiumForensics.toObject() : {};
  const confirmKey  = crypto.randomBytes(8).toString('hex');

  pendingDelete.set(confirmKey, {
    walletId:         wallet._id,
    walletAddress:    wallet.walletAddress,
    caseNumber:       wallet.caseNumber,
    premiumSnapshot:  currentData
  });
  // Auto-expire after 5 minutes
  setTimeout(() => pendingDelete.delete(confirmKey), 5 * 60 * 1000);

  const preview = buildDeletePreview(wallet.caseNumber, wallet.walletAddress, currentData);
  await bot.sendMessage(chatId, preview, {
    reply_markup: {
      inline_keyboard: [[
        { text: '🗑️ Delete', callback_data: `${CALLBACK.PREMIUM_DELETE}${confirmKey}` },
        { text: '❌ Cancel', callback_data: `cancel:delete:${confirmKey}` }
      ]]
    }
  });
});

// /cancel command — abort any active multi-step premium_add workflow
bot.onText(/^\/cancel$/, async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  const adminChatId = String(msg.chat.id);
  const state = workflowState.get(adminChatId);
  if (state) {
    workflowState.clear(adminChatId);
    await bot.sendMessage(chatId, '❌ Premium data workflow cancelled.');
  } else {
    await bot.sendMessage(chatId, 'No active workflow to cancel. Use /canceledit to cancel a field-edit prompt.');
  }
});

/**
 * Send the premium data confirmation preview after all workflow fields are
 * collected.  Stores the collected data in pendingPremiumData so that the
 * existing handlePremiumConfirm('add') handler can persist it on confirmation.
 *
 * @param {string} adminChatId  Stringified chat.id of the admin session.
 * @param {object} state        Completed workflow state object containing:
 *   - walletId      {string}  Mongoose ObjectId of the wallet document
 *   - walletAddress {string}  On-chain wallet address
 *   - caseNumber    {number}  Case number shown in the confirmation preview
 *   - collectedData {object}  Map of camelCase field names → validated values
 */
async function showWorkflowConfirmation(adminChatId, state) {
  const { walletId, walletAddress, caseNumber, collectedData } = state;
  const confirmKey = crypto.randomBytes(8).toString('hex');
  pendingPremiumData.set(confirmKey, {
    walletId,
    walletAddress,
    caseNumber,
    parsed: collectedData
  });
  setTimeout(() => pendingPremiumData.delete(confirmKey), 5 * 60 * 1000);

  const preview = buildPremiumPreview(caseNumber, walletAddress, collectedData);
  await bot.sendMessage(chatId, preview, {
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Confirm', callback_data: `premium:confirm:add:${confirmKey}` },
        { text: '❌ Cancel',  callback_data: `cancel:add:${confirmKey}` }
      ]]
    }
  });
}

// Multi-step premium workflow: receive and validate each field reply in sequence
bot.on('message', async (msg) => {
  if (String(msg.chat.id) !== String(chatId)) return;
  if (!msg.text) return;

  const adminChatId = String(msg.chat.id);
  const state = workflowState.get(adminChatId);
  if (!state || state.workflow !== 'premium_add') return;

  const text = msg.text.trim();

  // /cancel is handled by the dedicated onText handler above; re-check here as
  // a safety net so the workflow guard doesn't consume it and leave the session
  // open if the onText handler fires second.
  if (text === '/cancel') return;

  try {
    // /skip — leave the current field blank and advance to the next
    if (text === '/skip') {
      const currentIndex = PREMIUM_WORKFLOW_FIELDS.indexOf(state.currentField);
      const nextIndex    = currentIndex + 1;

      if (nextIndex >= PREMIUM_WORKFLOW_FIELDS.length) {
        workflowState.clear(adminChatId);
        await showWorkflowConfirmation(adminChatId, state);
      } else {
        const nextField = PREMIUM_WORKFLOW_FIELDS[nextIndex];
        workflowState.set(adminChatId, Object.assign({}, state, { currentField: nextField }));
        await bot.sendMessage(chatId, WORKFLOW_FIELD_PROMPTS[nextField]);
      }
      return;
    }

    // Ignore other slash commands while workflow is active
    if (text.startsWith('/')) return;

    // Parse the current field value (array fields require comma-splitting)
    const { currentField } = state;
    let parsedValue;
    if (ARRAY_PREMIUM_FIELDS.has(currentField)) {
      parsedValue = text.split(',').map(s => s.trim()).filter(Boolean);
    } else {
      parsedValue = text;
    }

    // Validate using the same rules as the PATCH endpoint
    const errors = validatePremiumFields({ [currentField]: parsedValue });
    if (errors.length > 0) {
      await bot.sendMessage(
        chatId,
        `❌ Invalid value:\n\n${errors.map(e => `• ${e}`).join('\n')}\n\nPlease try again or send /skip to leave blank.`
      );
      return;
    }

    // Store validated value and advance to next field
    const collectedData = Object.assign({}, state.collectedData, { [currentField]: parsedValue });
    const currentIndex  = PREMIUM_WORKFLOW_FIELDS.indexOf(currentField);
    const nextIndex     = currentIndex + 1;

    if (nextIndex >= PREMIUM_WORKFLOW_FIELDS.length) {
      // All 6 fields collected — show confirmation preview
      workflowState.clear(adminChatId);
      await showWorkflowConfirmation(adminChatId, Object.assign({}, state, { collectedData }));
    } else {
      const nextField = PREMIUM_WORKFLOW_FIELDS[nextIndex];
      workflowState.set(adminChatId, Object.assign({}, state, { currentField: nextField, collectedData }));
      await bot.sendMessage(chatId, WORKFLOW_FIELD_PROMPTS[nextField]);
    }
  } catch (err) {
    console.error('[bot] premium_add workflow error:', err);
    workflowState.clear(adminChatId);
    try {
      await bot.sendMessage(chatId, '❌ An error occurred during premium data entry. The workflow has been reset. Please try again.');
    } catch (_) { /* ignore secondary failure */ }
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
  if (ARRAY_PREMIUM_FIELDS.has(fieldName)) {
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
        { text: '✅ Confirm', callback_data: `premium:confirm:edit:${confirmKey}` },
        { text: '❌ Cancel',  callback_data: `cancel:edit:${confirmKey}` }
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
        { text: '✅ Confirm All', callback_data: `premium:confirm:bulk:${confirmKey}` },
        { text: '❌ Cancel',      callback_data: `cancel:bulk:${confirmKey}` }
      ]]
    }
  });
});

// ── Callback handlers ─────────────────────────────────────────────────────────
// Each handler receives (query, parts) where parts = query.data.split(':').
// All handlers must answer the callback query and return true on success.

/**
 * handle: review:<walletId>
 * Show wallet details to the admin.
 */
async function handleReview(query, parts) {
  const walletId = parts.slice(1).join(':');
  const wallet = await Wallet.findById(walletId);
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
  return true;
}

/**
 * handle: reject:<walletId>
 * Mark the case as rejected.
 */
async function handleReject(query, parts) {
  const walletId = parts.slice(1).join(':');
  const wallet = await Wallet.findById(walletId);
  if (!wallet) {
    return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
  }
  wallet.status = 'rejected';
  await wallet.save();
  await bot.answerCallbackQuery(query.id, { text: '❌ Case rejected.' });
  await bot.sendMessage(chatId, `❌ Case #${wallet.caseNumber} has been rejected.`);
  return true;
}

/**
 * handle: verify:<walletId>   (CALLBACK.VERIFY)
 * Verify the case and offer the Set Premium Forensics action.
 */
async function handleVerify(query, parts) {
  const walletId = parts.slice(1).join(':');
  const wallet = await Wallet.findById(walletId);
  if (!wallet) {
    return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
  }

  if (!wallet.forensic?.liquidityBefore) {
    return bot.answerCallbackQuery(query.id, { text: 'Isi forensic dulu!' });
  }

  wallet.status = 'verified';
  await wallet.save();

  await bot.sendMessage(chatId,
    `✅ Case #${wallet.caseNumber} Verified\nRisk Score: ${wallet.riskScore}`,
    {
      reply_markup: {
        inline_keyboard: [[
          { text: '🔐 Set Premium Forensics', callback_data: `setpremium:${wallet._id}` }
        ]]
      }
    }
  );
  return true;
}

/**
 * handle: setpremium:<walletId>
 * Prompt admin to send premium forensics in the legacy format.
 */
async function handleSetPremium(query, parts) {
  const walletId = parts.slice(1).join(':');
  const wallet = await Wallet.findById(walletId);
  if (!wallet) return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });

  await bot.answerCallbackQuery(query.id, { text: 'Kirim data premium forensic.' });
  await bot.sendMessage(chatId,
    `📋 Case #${wallet.caseNumber} — Premium Forensics\n\nKirim dengan format:\n\nAddLiquidityValue:\nRemoveLiquidityValue:\nWalletFunding:\nTokensCreated:\nForensicNotes:\nCrossProjectLinks:\nWalletId: ${wallet._id}`
  );
  return true;
}

/**
 * handle: premium:add:<walletId>   (CALLBACK.PREMIUM_ADD)
 * Start the multi-step premium data entry workflow for a wallet.
 *
 * Example callback_data: `premium:add:${wallet._id}`
 * Initializes workflowState for the admin's chat so that subsequent
 * plain-text replies are handled field-by-field by the workflow handler.
 */
async function handlePremiumAdd(query, parts) {
  // parts: ['premium', 'add', '<walletId>']
  const walletId = parts.slice(2).join(':');
  const wallet = await Wallet.findById(walletId);
  if (!wallet) {
    return bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
  }

  const adminChatId = String(query.message.chat.id);

  // Guard: if a workflow is already in progress, do not silently overwrite it.
  const existing = workflowState.get(adminChatId);
  if (existing) {
    await bot.answerCallbackQuery(query.id, { text: '⚠️ Workflow already active.' });
    await bot.sendMessage(
      chatId,
      `⚠️ You already have an active premium data entry in progress (Case #${existing.caseNumber}).\n\n` +
      `Send /cancel to discard it, then click [📝 Add Premium Data] again.`
    );
    return true;
  }

  // Initialize multi-step workflow state (auto-expires after 15 minutes of inactivity)
  workflowState.set(adminChatId, {
    workflow:      'premium_add',
    walletId:      wallet._id,
    walletAddress: wallet.walletAddress,
    caseNumber:    wallet.caseNumber,
    currentField:  PREMIUM_WORKFLOW_FIELDS[0],
    collectedData: {}
  });

  await bot.answerCallbackQuery(query.id, { text: 'Starting premium data entry…' });
  await bot.sendMessage(
    chatId,
    `📝 Premium data entry for Case #${wallet.caseNumber}\n(${wallet.walletAddress})\n\n` +
    `Answer each prompt in sequence.\nSend /skip to leave a field blank.\nSend /cancel to abort.\n\n` +
    WORKFLOW_FIELD_PROMPTS[PREMIUM_WORKFLOW_FIELDS[0]]
  );
  return true;
}

/**
 * handle: premium:edit:<field>:<walletId>   (CALLBACK.PREMIUM_EDIT)
 * Start a single-field edit prompt for a specific premium forensics field.
 *
 * Example callback_data: `premium:edit:addLiquidityValue:${wallet._id}`
 */
async function handlePremiumEdit(query, parts) {
  // parts: ['premium', 'edit', '<fieldName>', '<walletId>']
  const fieldName = parts[2];
  const walletId  = parts.slice(3).join(':');

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
    () => pendingFieldEdit.delete(String(query.message.chat.id)),
    10 * 60 * 1000
  );
  pendingFieldEdit.set(String(query.message.chat.id), {
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
  return true;
}

/**
 * handle: premium:confirm:<subtype>:<key>   (CALLBACK.PREMIUM_CONFIRM)
 * Confirm a pending premium data change.
 *
 * Subtypes:
 *   add  — confirm a full ADD_LIQ/... entry  (was confirmpremium)
 *   edit — confirm a single-field diff        (was confirmedit)
 *   bulk — confirm a NEW_VALUES bulk update   (was confirmbulkedit)
 *
 * Example callback_data: `premium:confirm:add:${confirmKey}`
 */
async function handlePremiumConfirm(query, parts) {
  // parts: ['premium', 'confirm', '<subtype>', '<key>']
  const subtype    = parts[2];
  const confirmKey = parts.slice(3).join(':');

  if (subtype === 'add') {
    const pendingData = pendingPremiumData.get(confirmKey);
    if (!pendingData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Please click [📝 Add Premium Data] again.'
      });
    }
    pendingPremiumData.delete(confirmKey);

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
    return true;
  }

  if (subtype === 'edit') {
    const confirmData = pendingEditConfirm.get(confirmKey);
    if (!confirmData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Use /edit_premium to start again.'
      });
    }
    pendingEditConfirm.delete(confirmKey);

    if (!checkAdminEditRateLimit(String(chatId))) {
      await bot.answerCallbackQuery(query.id, { text: '🚫 Rate limit reached.' });
      await bot.sendMessage(chatId, `🚫 Rate limit reached: max ${EDIT_RATE_LIMIT} edits per hour per admin. Please wait before making more changes.`);
      return true;
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
    return true;
  }

  if (subtype === 'bulk') {
    const bulkData = pendingBulkEdit.get(confirmKey);
    if (!bulkData) {
      return bot.answerCallbackQuery(query.id, {
        text: '❌ Confirmation expired. Use /edit_premium and send NEW_VALUES: ... again.'
      });
    }
    pendingBulkEdit.delete(confirmKey);

    if (!checkAdminEditRateLimit(String(chatId))) {
      await bot.answerCallbackQuery(query.id, { text: '🚫 Rate limit reached.' });
      await bot.sendMessage(chatId, `🚫 Rate limit reached: max ${EDIT_RATE_LIMIT} edits per hour per admin.`);
      return true;
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
    return true;
  }

  // Unknown subtype
  return false;
}

/**
 * handle: premium:delete:<confirmKey>   (CALLBACK.PREMIUM_DELETE)
 * Execute a confirmed premium data deletion for a wallet.
 *
 * The admin triggers this by sending /delete_premium [case|address], which
 * stores a premiumSnapshot in pendingDelete and shows a Confirm/Cancel prompt.
 * Clicking [🗑️ Delete] routes here to wipe all premiumForensics fields.
 */
async function handlePremiumDelete(query, parts) {
  // parts: ['premium', 'delete', '<confirmKey>']
  const confirmKey = parts.slice(2).join(':');
  const pending    = pendingDelete.get(confirmKey);

  if (!pending) {
    await bot.answerCallbackQuery(query.id, { text: '❌ Delete request expired or not found.' });
    return true;
  }

  pendingDelete.delete(confirmKey);

  const { walletId, walletAddress, caseNumber, premiumSnapshot } = pending;

  const wallet = await Wallet.findById(walletId).select('+premiumForensics');
  if (!wallet) {
    await bot.answerCallbackQuery(query.id, { text: '❌ Wallet not found.' });
    return true;
  }

  if (wallet.status !== 'verified') {
    await bot.answerCallbackQuery(query.id, { text: '❌ Wallet is no longer verified.' });
    return true;
  }

  // Clear all premiumForensics fields
  if (wallet.premiumForensics) {
    for (const field of PREMIUM_WORKFLOW_FIELDS) {
      wallet.premiumForensics[field] = undefined;
    }
  }
  await wallet.save();

  await writeAuditLog({
    action:        'premium_delete',
    walletAddress,
    caseNumber,
    changedBy:     { source: 'telegram', identifier: String(query.from?.id || 'unknown') },
    fieldsChanged: Object.keys(premiumSnapshot).filter(k => premiumSnapshot[k] !== undefined),
    before:        premiumSnapshot,
    after:         {},
    ipHash:        null
  });

  await bot.answerCallbackQuery(query.id, { text: '🗑️ Deleted.' });
  await bot.sendMessage(
    chatId,
    `🗑️ Premium data deleted for Case #${caseNumber}\n(${walletAddress})`
  );
  return true;
}

/**
 * handle: cancel:<subtype>:<key>   (CALLBACK.CANCEL)
 * Cancel a pending premium data change.
 *
 * Subtypes:
 *   add    — cancel a full ADD_LIQ/... entry  (was cancelpremium)
 *   edit   — cancel a single-field diff        (was canceledit)
 *   bulk   — cancel a NEW_VALUES bulk update   (was cancelbulkedit)
 *   delete — cancel a pending premium delete
 *
 * Example callback_data: `cancel:add:${confirmKey}`
 */
async function handleCancel(query, parts) {
  // parts: ['cancel', '<subtype>', '<key>']
  const subtype    = parts[1];
  const confirmKey = parts.slice(2).join(':');

  if (subtype === 'add') {
    pendingPremiumData.delete(confirmKey);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Premium data entry cancelled.');
    return true;
  }

  if (subtype === 'edit') {
    pendingEditConfirm.delete(confirmKey);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Field edit cancelled.');
    return true;
  }

  if (subtype === 'bulk') {
    pendingBulkEdit.delete(confirmKey);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Bulk edit cancelled.');
    return true;
  }

  if (subtype === 'delete') {
    pendingDelete.delete(confirmKey);
    await bot.answerCallbackQuery(query.id, { text: 'Cancelled.' });
    await bot.sendMessage(chatId, '❌ Premium data deletion cancelled.');
    return true;
  }

  // Unknown subtype
  return false;
}

/**
 * Route a Telegram callback_query to the correct handler based on its
 * callback_data prefix (using the CALLBACK constant prefixes).
 *
 * Routing table:
 *   CALLBACK.VERIFY          ('verify:')          → handleVerify
 *   CALLBACK.PREMIUM_ADD     ('premium:add:')      → handlePremiumAdd
 *   CALLBACK.PREMIUM_EDIT    ('premium:edit:')     → handlePremiumEdit
 *   CALLBACK.PREMIUM_CONFIRM ('premium:confirm:')  → handlePremiumConfirm
 *   CALLBACK.PREMIUM_DELETE  ('premium:delete:')   → handlePremiumDelete
 *   CALLBACK.CANCEL          ('cancel')            → handleCancel
 *   'review:'                                      → handleReview
 *   'reject:'                                      → handleReject
 *   'setpremium:'                                  → handleSetPremium
 *
 * @param {object} query - Telegram callback_query object
 * @returns {Promise<boolean>} true if the query was handled; false if the
 *   prefix was unrecognised (caller should send an "Unknown action" response)
 */
async function routeCallback(query) {
  const data  = query.data || '';
  const parts = data.split(':');

  if (data.startsWith(CALLBACK.PREMIUM_CONFIRM)) return handlePremiumConfirm(query, parts);
  if (data.startsWith(CALLBACK.PREMIUM_ADD))     return handlePremiumAdd(query, parts);
  if (data.startsWith(CALLBACK.PREMIUM_EDIT))    return handlePremiumEdit(query, parts);
  if (data.startsWith(CALLBACK.PREMIUM_DELETE))  return handlePremiumDelete(query, parts);
  if (data.startsWith(CALLBACK.VERIFY))          return handleVerify(query, parts);
  if (data.startsWith(CALLBACK.CANCEL))          return handleCancel(query, parts);
  if (data.startsWith('review:'))                return handleReview(query, parts);
  if (data.startsWith('reject:'))                return handleReject(query, parts);
  if (data.startsWith('setpremium:'))            return handleSetPremium(query, parts);

  return false;
}

bot.on('callback_query', async (query) => {
  // Verify the callback originates from an authorized admin chat and user
  if (!telegramAdminAuth(query)) {
    await bot.answerCallbackQuery(query.id, { text: '⛔ Unauthorized.' });
    return;
  }

  try {
    if (!await routeCallback(query)) {
      await bot.answerCallbackQuery(query.id, { text: 'Unknown action' });
    }
  } catch (err) {
    console.error('[bot] callback_query error:', err);
    try {
      await bot.answerCallbackQuery(query.id, { text: '❌ An error occurred. Please try again.' });
    } catch (_) { /* ignore secondary failure */ }
  }
});

// Periodic cleanup: remove any workflow states that have exceeded 15 minutes.
// The per-entry setTimeout already handles expiry; this job is a safety net.
setInterval(() => workflowState.cleanup(), 5 * 60 * 1000);

/**
 * ==========================
 * ROUTES
 * ==========================
 */

// HEALTH CHECK
// curl -s https://suspected.dev/api/health | jq .
app.get('/api/health', (_req, res) => {
  const dbState = mongoose.connection.readyState;
  // 0=disconnected, 1=connected, 2=connecting, 3=disconnecting
  const dbStatus = ['disconnected', 'connected', 'connecting', 'disconnecting'][dbState] || 'unknown';
  const isHealthy = dbState === 1;
  res.status(isHealthy ? 200 : 503).json({
    success: isHealthy,
    status: isHealthy ? 'ok' : 'degraded',
    db: dbStatus,
    timestamp: new Date().toISOString()
  });
});

// PUBLIC LIST
app.get('/api/wallets', async (req, res) => {
  try {
    const limitParam = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(limitParam) && limitParam > 0 && limitParam <= 1000 ? limitParam : 0;
    let query = Wallet.find({ status: 'verified' })
      .select('-forensic -premiumForensics -__v');
    if (limit > 0) query = query.limit(limit);
    const wallets = await query;
    res.json({ success: true, data: wallets.map(w => formatWalletResponse(w)) });
  } catch (err) {
    console.error('GET /api/wallets error:', err.message);
    res.status(500).json({ success: false, message: 'Internal server error' });
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

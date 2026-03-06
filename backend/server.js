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

// Audit logger — writes only to admin_audit.log, never to console
const AUDIT_LOG_PATH = path.join(__dirname, 'admin_audit.log');
function writeAdminAuditLog(entry) {
  const line = JSON.stringify(entry) + '\n';
  fs.appendFile(AUDIT_LOG_PATH, line, () => { /* intentionally silent */ });
}

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

// STEP 1: Admin isi forensic data
const requestForensicInput = async (wallet) => {
  await bot.sendMessage(chatId,
    `📋 Case #${wallet.caseNumber}

Isi forensic data dengan format:

LiquidityBefore:
LiquidityAfter:
DrainDurationHours:
DetectedPattern:
WalletFunding:
`
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

// STEP 3: Verify only after forensic filled
bot.on('callback_query', async (query) => {
  // Only process callbacks from the authorized chat
  if (String(query.message?.chat?.id) !== String(chatId)) return;

  const [action, id] = query.data.split('_');

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
    res.json(wallets);
  } catch (err) {
    console.error('GET /api/wallets error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PUBLIC DETAIL
app.get('/api/wallets/:address', async (req, res) => {
  try {
    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      status: 'verified'
    }).select('-forensic -premiumForensics -__v');

    if (!wallet) return res.status(404).json({ message: 'Not found' });

    res.json(wallet);
  } catch (err) {
    console.error('GET /api/wallets/:address error:', err.message);
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
 */
app.get('/api/wallets/:address/premium', async (req, res) => {

  const paid = req.headers['x402-payment'];
  const validPaymentToken = process.env.X402_PAYMENT_SECRET;

  if (!paid || !validPaymentToken) {
    return res.status(402).json({
      message: 'Payment required via x402'
    });
  }

  // Use timing-safe comparison to prevent timing attacks
  try {
    const paidBuf = Buffer.from(paid);
    const validBuf = Buffer.from(validPaymentToken);
    if (paidBuf.length !== validBuf.length || !crypto.timingSafeEqual(paidBuf, validBuf)) {
      return res.status(402).json({
        message: 'Payment required via x402'
      });
    }
  } catch {
    return res.status(402).json({ message: 'Payment required via x402' });
  }

  try {
    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      status: 'verified'
    });

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
    const wallet = await Wallet.findOne({ walletAddress: req.params.address });
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
 * Accepts: TELEGRAM_ADMIN_TOKEN header OR x402-payment + x-admin-token (admin role)
 * Rate limited: 20 updates per hour per admin token
 */
app.patch('/api/admin/wallets/:address/premium', adminPremiumRateLimit, async (req, res) => {
  // ── Authorization ──────────────────────────────────────────────────────────
  let authorized = false;

  // Option 1: Telegram admin token
  const telegramAdminToken = req.headers['x-telegram-admin-token'];
  const validTelegramToken = process.env.TELEGRAM_ADMIN_TOKEN;
  if (telegramAdminToken && validTelegramToken) {
    try {
      const aBuf = Buffer.from(telegramAdminToken);
      const bBuf = Buffer.from(validTelegramToken);
      if (aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf)) {
        authorized = true;
      }
    } catch { /* fall through */ }
  }

  // Option 2: Valid x402 payment header AND valid admin token (admin role check)
  if (!authorized) {
    const x402Payment = req.headers['x402-payment'];
    const validX402 = process.env.X402_PAYMENT_SECRET;
    const adminToken = req.headers['x-admin-token'];
    const validAdminSecret = process.env.ADMIN_SECRET;

    if (x402Payment && validX402 && adminToken && validAdminSecret) {
      try {
        const paidBuf = Buffer.from(x402Payment);
        const validPaidBuf = Buffer.from(validX402);
        const adminBuf = Buffer.from(adminToken);
        const validAdminBuf = Buffer.from(validAdminSecret);
        const x402Valid = paidBuf.length === validPaidBuf.length &&
          crypto.timingSafeEqual(paidBuf, validPaidBuf);
        const adminValid = adminBuf.length === validAdminBuf.length &&
          crypto.timingSafeEqual(adminBuf, validAdminBuf);
        if (x402Valid && adminValid) authorized = true;
      } catch { /* fall through */ }
    }
  }

  if (!authorized) {
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

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
    if (typeof forensicNotes !== 'string') {
      errors.push('forensicNotes must be a string');
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
    const wallet = await Wallet.findOne({ walletAddress: req.params.address });
    if (!wallet) return res.status(404).json({ success: false, message: 'Not found' });

    const fieldsChanged = [];
    const update = { updatedAt: new Date() };

    if (addLiquidityValue !== undefined)   { update.addLiquidityValue   = addLiquidityValue;   fieldsChanged.push('addLiquidityValue'); }
    if (removeLiquidityValue !== undefined) { update.removeLiquidityValue = removeLiquidityValue; fieldsChanged.push('removeLiquidityValue'); }
    if (walletFunding !== undefined)        { update.walletFunding        = walletFunding;        fieldsChanged.push('walletFunding'); }
    if (tokensCreated !== undefined)        { update.tokensCreated        = tokensCreated;        fieldsChanged.push('tokensCreated'); }
    if (forensicNotes !== undefined)        { update.forensicNotes        = forensicNotes;        fieldsChanged.push('forensicNotes'); }
    if (crossProjectLinks !== undefined)    { update.crossProjectLinks    = crossProjectLinks;    fieldsChanged.push('crossProjectLinks'); }

    wallet.set('premiumForensics', Object.assign(
      wallet.premiumForensics ? wallet.premiumForensics.toObject() : {},
      update
    ));
    await wallet.save();

    const auditEntry = {
      updatedBy: 'admin',
      timestamp: new Date().toISOString(),
      fieldsChanged,
      walletAddress: req.params.address
    };
    writeAdminAuditLog(auditEntry);

    return res.json({
      success: true,
      premiumForensics: wallet.premiumForensics,
      auditLog: {
        updatedBy: auditEntry.updatedBy,
        timestamp: auditEntry.timestamp,
        fieldsChanged: auditEntry.fieldsChanged
      }
    });
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

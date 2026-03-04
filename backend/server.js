require('dotenv').config();

const crypto = require('crypto');
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
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x402-payment']
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

// STEP 3: Verify only after forensic filled
bot.on('callback_query', async (query) => {
  // Only process callbacks from the authorized chat
  if (String(query.message?.chat?.id) !== String(chatId)) return;

  const [action, id] = query.data.split('_');

  if (action !== 'verify') return;

  const wallet = await Wallet.findById(id);

  if (!wallet.forensic?.liquidityBefore) {
    return bot.answerCallbackQuery(query.id, {
      text: 'Isi forensic dulu!'
    });
  }

  wallet.status = 'verified';
  await wallet.save();

  await bot.sendMessage(chatId,
    `✅ Case #${wallet.caseNumber} Verified\nRisk Score: ${wallet.riskScore}`
  );
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
      .select('-forensic -__v');
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
    }).select('-forensic -__v');

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
    if (!wallet.forensic) return res.status(404).json({ message: 'Forensic data not available' });

    res.json(wallet.forensic);
  } catch (err) {
    console.error('GET /api/wallets/:address/premium error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`);
  if (!process.env.X402_PAYMENT_SECRET) {
    console.warn('WARNING: X402_PAYMENT_SECRET is not set. The premium endpoint will reject all requests.');
  }
});

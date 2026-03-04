require('dotenv').config();

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
    }).select('-forensic');

    if (!wallet) return res.status(404).json({ message: 'Not found' });

    res.json(wallet);
  } catch (err) {
    console.error('GET /api/wallets/:address error:', err.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * PREMIUM ENDPOINT (x402 REQUIRED)
 */
app.get('/api/wallets/:address/premium', async (req, res) => {

  const paid = req.headers['x402-payment'];
  const validPaymentToken = process.env.X402_PAYMENT_SECRET;

  if (!paid || !validPaymentToken || paid !== validPaymentToken) {
    return res.status(402).json({
      message: 'Payment required via x402'
    });
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

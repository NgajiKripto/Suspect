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
app.use(cors());
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
  if (!msg.text.includes('LiquidityBefore')) return;

  const lines = msg.text.split('\n');
  const data = {};

  lines.forEach(line => {
    const [key, value] = line.split(':');
    if (key && value) data[key.trim()] = value.trim();
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
  const wallets = await Wallet.find({ status: 'verified' })
    .select('-forensic -__v');
  res.json(wallets);
});

// PUBLIC DETAIL
app.get('/api/wallets/:address', async (req, res) => {
  const wallet = await Wallet.findOne({
    walletAddress: req.params.address,
    status: 'verified'
  }).select('-forensic');

  if (!wallet) return res.status(404).json({ message: 'Not found' });

  res.json(wallet);
});

/**
 * PREMIUM ENDPOINT (x402 REQUIRED)
 */
app.get('/api/wallets/:address/premium', async (req, res) => {

  const paid = req.headers['x402-payment'];

  if (!paid || paid !== 'valid') {
    return res.status(402).json({
      message: 'Payment required via x402'
    });
  }

  const wallet = await Wallet.findOne({
    walletAddress: req.params.address,
    status: 'verified'
  });

  res.json(wallet.forensic);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`);
});

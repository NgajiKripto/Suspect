/**
 * =========================================
 * ENV & DEPENDENCIES
 * =========================================
 */
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const TelegramBot = require('node-telegram-bot-api');

const Wallet = require('./models/Wallet');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
/**
 * =========================================
 * TELEGRAM BOT (FINAL - POLLING)
 * =========================================
 */
const botToken = process.env.TELEGRAM_BOT_TOKEN;
const chatId = process.env.TELEGRAM_CHAT_ID; // WAJIB isi dengan chat id Anda

let bot = null;

if (!botToken) {
  console.error('❌ TELEGRAM_BOT_TOKEN tidak ada');
} else {
  bot = new TelegramBot(botToken, { polling: true });
  console.log('✅ Telegram Bot Connected (polling)');
}

// Helper kirim pesan
const sendTelegram = async (message, options = {}) => {
  if (!bot || !chatId) return;
  try {
    await bot.sendMessage(chatId, message, {
      parse_mode: 'HTML',
      disable_web_page_preview: true,
      ...options
    });
  } catch (err) {
    console.error('❌ Telegram Error:', err.message);
  }
};

// Handle tombol Verify / Reject
bot?.on('callback_query', async (query) => {
  const [action, walletId] = query.data.split('_');
  const admin = query.from.username || 'unknown';

  if (!['verify', 'reject'].includes(action)) return;

  try {
    await Wallet.findByIdAndUpdate(walletId, {
      status: action === 'verify' ? 'verified' : 'rejected',
      'verification.verifiedBy': admin,
      'verification.verifiedAt': new Date()
    });

    await bot.answerCallbackQuery(query.id, {
      text: action === 'verify' ? '✅ Diverifikasi' : '❌ Ditolak'
    });

    await bot.sendMessage(
      query.message.chat.id,
      `${action === 'verify' ? '✅' : '❌'} Case ${walletId} ${action} oleh @${admin}`
    );
  } catch (err) {
    console.error('Telegram callback error:', err.message);
  }
});

/**
 * =========================================
 * MIDDLEWARE
 * =========================================
 */
app.use(cors());
app.use(express.json());

app.use(
  '/api/',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
  })
);

/**
 * =========================================
 * DATABASE
 * =========================================
 */
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Error:', err);
    process.exit(1);
  });

/**
 * =========================================
 * ROUTES
 * =========================================
 */

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', time: new Date() });
});

// GET wallets
app.get('/api/wallets', async (req, res) => {
  try {
    const { status = 'verified', limit = 50 } = req.query;

    const query = { isActive: true };
    if (status !== 'all') {
      query.status = status;
    }

    const wallets = await Wallet.find(query)
      .sort({ riskScore: -1, caseNumber: -1 })
      .limit(parseInt(limit))
      .select('-__v');

    res.json({ success: true, count: wallets.length, data: wallets });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET wallet by address
app.get('/api/wallets/:address', async (req, res) => {
  try {
    const wallet = await Wallet.findOne({
      walletAddress: req.params.address,
      isActive: true
    });

    if (!wallet) {
      return res.status(404).json({ success: false, message: 'Wallet not found' });
    }

    res.json({ success: true, data: wallet });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST wallet report
app.post('/api/wallets', async (req, res) => {
  try {
    const { walletAddress, evidence = {}, projectName, tokenAddress } = req.body;

    const base58Regex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
    if (!base58Regex.test(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Solana wallet address'
      });
    }

    let wallet = await Wallet.findOne({ walletAddress });

    if (wallet) {
      wallet.reportCount += 1;
      wallet.lastUpdated = new Date();
      await wallet.save();

      return res.json({
        success: true,
        message: 'Report added to existing case',
        data: wallet
      });
    }

    wallet = new Wallet({
      walletAddress,
      projectName,
      tokenAddress,
      evidence: {
        txHash: evidence.txHash,
        solscanLink: evidence.solscanLink,
        description: evidence.description
      },
      status: 'pending'
    });

    await wallet.save();

    // 🔔 Telegram notification
    await sendTelegram(
      `
🚨 <b>LAPORAN BARU MASUK</b>

📋 Case #${wallet.caseNumber}
👛 <code>${wallet.walletAddress}</code>
📊 Status: ${wallet.status.toUpperCase()}
🎯 Risk: ${wallet.riskScore}/100
🕒 ${new Date().toLocaleString()}

📝 ${wallet.evidence.description || '-'}
`,
      {
        reply_markup: {
          inline_keyboard: [[
            { text: '✅ Verifikasi', callback_data: `verify_${wallet._id}` },
            { text: '❌ Tolak', callback_data: `reject_${wallet._id}` }
          ]]
        }
      }
    );

    res.status(201).json({
      success: true,
      message: 'Report submitted',
      data: wallet
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * =========================================
 * START SERVER (PM2 SAFE)
 * =========================================
 */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} already in use`);
    process.exit(1);
  }
});

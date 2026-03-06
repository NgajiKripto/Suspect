const mongoose = require('mongoose');

/**
 * ==========================
 * COUNTER (Atomic Case Number)
 * ==========================
 */
const counterSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  seq: { type: Number, default: 0 }
});
const Counter = mongoose.model('Counter', counterSchema);

/**
 * ==========================
 * WALLET SCHEMA
 * ==========================
 */
const walletSchema = new mongoose.Schema({
  walletAddress: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  caseNumber: { type: Number, unique: true },

  status: {
    type: String,
    enum: ['pending', 'investigating', 'verified', 'rejected'],
    default: 'pending',
    index: true
  },

  riskScore: { type: Number, default: 0, max: 100, index: true },

  projectName: String,
  tokenAddress: String,

  evidence: {
    txHash: String,
    solscanLink: String,
    description: String,
    submittedAt: { type: Date, default: Date.now }
  },

  // 🔴 PREMIUM FORENSIC DATA
  forensic: {
    liquidityBefore: Number,
    liquidityAfter: Number,
    drainDurationHours: Number,
    detectedPattern: { type: [String], default: [] },
    walletFunding: String
  },

  // 🔐 PREMIUM FORENSICS — x402 gated ($0.11 payment required)
  premiumForensics: {
    addLiquidityValue: { type: String, default: null },      // Value saat add liquidity, e.g. "45.2 SOL"
    removeLiquidityValue: { type: String, default: null },   // Value saat remove liquidity, e.g. "0.3 SOL"
    walletFunding: { type: String, default: null },          // Source of initial funds, e.g. "Tornado Cash"
    tokensCreated: { type: [String], default: [] },          // List token yang pernah dibuat
    forensicNotes: { type: String, default: null },          // Admin internal notes on pattern analysis
    crossProjectLinks: { type: [String], default: [] },      // Related wallets showing repeat offender pattern
    updatedAt: { type: Date, default: null }
  },

  reportCount: { type: Number, default: 1 },
  isActive: { type: Boolean, default: true }

}, { timestamps: true });

// Index for efficient cross-reference queries on tokensCreated
walletSchema.index({ 'premiumForensics.tokensCreated': 1 });

/**
 * ==========================
 * RISK ENGINE
 * ==========================
 */
walletSchema.methods.calculateRiskScore = function () {
  if (this.forensic?.liquidityAfter === 0 &&
      this.forensic?.liquidityBefore > 0) {
    this.riskScore = 100;
    return 100;
  }

  let score = 0;

  if (this.forensic?.liquidityAfter < this.forensic?.liquidityBefore)
    score += 40;

  if (this.forensic?.detectedPattern?.includes('liquidity_removal'))
    score += 40;

  this.riskScore = Math.min(score, 99);
  return this.riskScore;
};

/**
 * ==========================
 * PRE SAVE
 * ==========================
 */
walletSchema.pre('save', async function (next) {

  if (this.isNew) {
    const counter = await Counter.findOneAndUpdate(
      { name: 'walletCase' },
      { $inc: { seq: 1 } },
      { new: true, upsert: true }
    );
    this.caseNumber = counter.seq;
  }

  this.calculateRiskScore();
  next();
});

module.exports = mongoose.model('Wallet', walletSchema);

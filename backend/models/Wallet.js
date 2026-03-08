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
 * SOLANA BASE58 VALIDATOR
 * ==========================
 * Validates a Solana-compatible Base58-encoded address (32–44 chars,
 * excludes ambiguous characters 0, O, I, l).
 * Mirrors the WALLET_ADDRESS_REGEX used in server.js.
 */
const SOLANA_BASE58_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function validateSolanaBase58(addr) {
  return typeof addr === 'string' && SOLANA_BASE58_REGEX.test(addr);
}

/**
 * ==========================
 * PREMIUM FORENSICS SUB-SCHEMA
 * ==========================
 * Defined separately so that select: false can be applied to the
 * entire premiumForensics path, keeping it out of default query
 * results unless explicitly requested with +premiumForensics.
 */
const premiumForensicsSchema = new mongoose.Schema({
  addLiquidityValue:    { type: String, default: null, maxlength: 50 },
  removeLiquidityValue: { type: String, default: null, maxlength: 50 },
  walletFunding:        { type: String, default: null, maxlength: 200 },
  tokensCreated: {
    type: [String],
    default: [],
    validate: { validator: v => v.every(validateSolanaBase58), message: 'Invalid token address' }
  },
  forensicNotes:  { type: String, default: null, maxlength: 500 },
  crossProjectLinks: {
    type: [String],
    default: [],
    validate: { validator: v => v.every(validateSolanaBase58), message: 'Invalid wallet address' }
  },
  updatedAt: { type: Date, default: null }
}, { _id: false });

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
  // select: false ensures this subdocument is NEVER included in query
  // results by default; use .select('+premiumForensics') to include it.
  premiumForensics: {
    type: premiumForensicsSchema,
    select: false
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
 * toPublicJSON
 * ==========================
 * Returns a plain object safe for API responses.
 * premiumForensics is only included when hasPremiumAccess === true
 * (i.e. the caller has supplied a valid x402 payment and the query
 * used .select('+premiumForensics') to hydrate the field).
 */
walletSchema.methods.toPublicJSON = function (hasPremiumAccess) {
  const { premiumForensics: _pf, ...obj } = this.toObject({ versionKey: false });
  if (hasPremiumAccess === true) {
    obj.premiumForensics = this.premiumForensics || null;
  }
  return obj;
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
module.exports.validateSolanaBase58 = validateSolanaBase58;

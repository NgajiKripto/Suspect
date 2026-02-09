const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  walletAddress: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  caseNumber: {
    type: Number,
    required: false,
    unique: true
  },
  status: {
    type: String,
    enum: ['pending', 'investigating', 'verified', 'rejected'],
    default: 'pending'
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  projectName: String,
  tokenAddress: String,
  evidence: {
    txHash: String,
    solscanLink: String,
    description: String,
    submittedAt: { type: Date, default: Date.now }
  },
  verification: {
    verifiedBy: String,
    verifiedAt: Date,
    notes: String,
    solscanChecked: { type: Boolean, default: false },
    liquidityLocked: { type: Boolean, default: false },
    liquidityAmount: Number,
    victimsLoss: { type: Number, default: 0 },
    patternFound: [String]
  },
  firstSeen: { type: Date, default: Date.now },
  lastUpdated: { type: Date, default: Date.now },
  reportCount: { type: Number, default: 1 },
  isActive: { type: Boolean, default: true }
});

walletSchema.pre('save', async function(next) {
  if (this.isNew && !this.caseNumber) {
    const lastWallet = await this.constructor.findOne().sort({ caseNumber: -1 });
    this.caseNumber = lastWallet ? lastWallet.caseNumber + 1 : 1;
  }
  this.lastUpdated = new Date();
  next();
});

walletSchema.methods.calculateRiskScore = function() {
  let score = 0;
  if (this.status === 'verified') score += 30;
  if (this.verification.liquidityLocked === false) score += 40;
  if (this.verification.victimsLoss > 100000) score += 20;
  else if (this.verification.victimsLoss > 50000) score += 15;
  else if (this.verification.victimsLoss > 10000) score += 10;
  const patterns = this.verification.patternFound || [];
  if (patterns.includes('liquidity_removal')) score += 10;
  if (patterns.includes('team_dump')) score += 10;
  this.riskScore = Math.min(score, 100);
  return this.riskScore;
};

module.exports = mongoose.model('Wallet', walletSchema);

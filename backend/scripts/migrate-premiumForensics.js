/**
 * Migration: initialise empty premiumForensics on existing Wallet documents
 *
 * Adds a premiumForensics sub-document with all default values to any Wallet
 * that does not yet have one.  The script is idempotent — running it multiple
 * times will not overwrite documents that already have premiumForensics data.
 *
 * Usage:
 *   MONGODB_URI=mongodb://... node backend/scripts/migrate-premiumForensics.js
 */

'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('MONGODB_URI environment variable is required.');
    process.exit(1);
  }

  await mongoose.connect(uri);
  console.log('MongoDB connected.');

  const result = await mongoose.connection
    .collection('wallets')
    .updateMany(
      // Only update documents that have no premiumForensics subdocument at all
      { premiumForensics: { $exists: false } },
      {
        $set: {
          premiumForensics: {
            addLiquidityValue:    null,
            removeLiquidityValue: null,
            walletFunding:        null,
            tokensCreated:        [],
            forensicNotes:        null,
            crossProjectLinks:    [],
            updatedAt:            null
          }
        }
      }
    );

  console.log(`Migration complete. Documents updated: ${result.modifiedCount}`);
  await mongoose.disconnect();
}

run().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});

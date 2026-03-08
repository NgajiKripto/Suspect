/**
 * Migration: add empty premiumForensics field to existing Wallet documents
 *
 * Finds every Wallet document that has no premiumForensics field and sets it
 * to an empty object so Mongoose can apply schema defaults on next access.
 * The script is idempotent — running it again skips documents that already
 * have the field, so no existing data is ever overwritten.
 *
 * Usage:
 *   node backend/scripts/migrate-premium-forensics.js            # live run
 *   node backend/scripts/migrate-premium-forensics.js --dry-run  # preview only
 */

'use strict';

require('dotenv').config();
const mongoose = require('mongoose');
const Wallet   = require('../models/Wallet');

const DRY_RUN = process.argv.includes('--dry-run');

const LOG_INTERVAL = 100; // log progress every N documents

async function run() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('Error: MONGODB_URI environment variable is required.');
    process.exit(1);
  }

  if (DRY_RUN) {
    console.log('[dry-run] No changes will be written to the database.');
  }

  await mongoose.connect(uri);
  console.log('MongoDB connected.');

  // Use lean() for a lightweight read — we only need _id for the update loop.
  const docs = await Wallet
    .find({ premiumForensics: { $exists: false } }, { _id: 1 })
    .lean();

  const total = docs.length;
  console.log(`Found ${total} document(s) missing premiumForensics.`);

  if (total === 0) {
    console.log('Nothing to do — migration is already complete.');
    await mongoose.disconnect();
    return;
  }

  let updated = 0;
  let failed  = 0;

  for (let i = 0; i < docs.length; i++) {
    const doc = docs[i];

    try {
      if (DRY_RUN) {
        // In dry-run mode count only what would be affected; no DB writes.
        updated++;
      } else {
        // Re-check the condition inside the filter to stay idempotent even if
        // the script is run concurrently; $exists: false ensures we never
        // overwrite a field that appeared between the find and this update.
        const result = await Wallet.updateOne(
          { _id: doc._id, premiumForensics: { $exists: false } },
          { $set: { premiumForensics: {} } }
        );
        // Only count documents that were actually modified in the database.
        if (result.modifiedCount > 0) {
          updated++;
        }
      }
    } catch (err) {
      failed++;
      console.error(`Error updating document ${doc._id}: ${err.message}`);
    }

    const processed = i + 1;
    if (processed % LOG_INTERVAL === 0 || processed === total) {
      console.log(`Processed ${processed}/${total} documents, updated ${updated}`);
    }
  }

  const mode = DRY_RUN ? ' (dry-run)' : '';
  const label = DRY_RUN ? 'Would update' : 'Updated';
  console.log(`\nMigration complete${mode}.`);
  console.log(`Total found: ${total} | ${label}: ${updated} | Failed: ${failed}`);

  await mongoose.disconnect();

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});

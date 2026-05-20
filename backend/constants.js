'use strict';

/**
 * Shared validation constants for suspected.dev backend.
 *
 * Single source of truth for all regex patterns and validation rules.
 * Import these instead of re-declaring them in individual files.
 */

// Solana Base58 address: 32-44 characters, no ambiguous chars (0, O, I, l)
const WALLET_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

// Transaction hash: Base58, 1-100 characters
const TX_HASH_REGEX = /^[1-9A-HJ-NP-Za-km-z]{1,100}$/;

// Liquidity value format: number followed by optional currency
const LIQUIDITY_VALUE_REGEX = /^\d+(\.\d+)?\s*(SOL|USDC|USD)?$/i;

// Simple HTML tag detection (used to reject HTML in text fields)
const HTML_TAG_REGEX = /<[^>]*>/;

// Maximum field lengths
const MAX_DESCRIPTION_LENGTH = 500;
const MAX_PROJECT_NAME_LENGTH = 100;
const MAX_WALLET_FUNDING_LENGTH = 200;

module.exports = {
  WALLET_ADDRESS_REGEX,
  TX_HASH_REGEX,
  LIQUIDITY_VALUE_REGEX,
  HTML_TAG_REGEX,
  MAX_DESCRIPTION_LENGTH,
  MAX_PROJECT_NAME_LENGTH,
  MAX_WALLET_FUNDING_LENGTH
};

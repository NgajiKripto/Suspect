'use strict';

/**
 * Multi-step workflow state manager.
 *
 * State shape stored per chatId:
 * {
 *   workflow:      'premium_add' | 'premium_edit',
 *   walletId:      string,
 *   walletAddress: string,
 *   caseNumber:    number|string,
 *   currentField:  string,
 *   collectedData: { [field]: value },
 *   startedAt:     number  (Unix ms timestamp)
 * }
 *
 * Interface is designed to allow a Redis swap later:
 *   - get(chatId)         → state | null
 *   - set(chatId, state)  → void  (resets expiry)
 *   - clear(chatId)       → void
 *   - touch(chatId)       → void  (extends expiry without changing state)
 *   - cleanup()           → void  (called by periodic job)
 */

const WORKFLOW_EXPIRE_MS = 15 * 60 * 1000; // 15 minutes

// Internal store: chatId (string) → { state: object, timerId: NodeJS.Timeout }
const _store = new Map();

/**
 * Retrieve the active workflow state for a chat session.
 * Returns null if no state exists or if it has already expired.
 *
 * @param {string|number} chatId
 * @returns {object|null}
 */
function get(chatId) {
  const entry = _store.get(String(chatId));
  return entry ? entry.state : null;
}

/**
 * Create or overwrite the workflow state for a chat session.
 * Automatically resets the 15-minute inactivity expiry timer.
 * All state writes are synchronous — safe within Node's single-threaded
 * event loop without additional locking.
 *
 * @param {string|number} chatId
 * @param {object}        state  Must include at minimum: workflow, currentField, collectedData
 */
function set(chatId, state) {
  const key = String(chatId);
  const existing = _store.get(key);
  if (existing) clearTimeout(existing.timerId);

  const timerId = setTimeout(() => _store.delete(key), WORKFLOW_EXPIRE_MS);
  _store.set(key, {
    state: Object.assign({ startedAt: Date.now() }, state),
    timerId
  });
}

/**
 * Delete the workflow state for a chat session and cancel its expiry timer.
 *
 * @param {string|number} chatId
 */
function clear(chatId) {
  const key = String(chatId);
  const existing = _store.get(key);
  if (existing) clearTimeout(existing.timerId);
  _store.delete(key);
}

/**
 * Reset the inactivity expiry timer for an existing state without modifying
 * the state itself.  No-op if no state exists for the given chatId.
 *
 * @param {string|number} chatId
 */
function touch(chatId) {
  const key = String(chatId);
  const existing = _store.get(key);
  if (!existing) return;
  clearTimeout(existing.timerId);
  existing.timerId = setTimeout(() => _store.delete(key), WORKFLOW_EXPIRE_MS);
}

/**
 * Remove all state entries whose startedAt timestamp is older than
 * WORKFLOW_EXPIRE_MS.  Intended to be called by a periodic cleanup job
 * as a safety net in addition to the per-entry setTimeout.
 */
function cleanup() {
  const now = Date.now();
  for (const [key, entry] of _store) {
    if (now - entry.state.startedAt > WORKFLOW_EXPIRE_MS) {
      clearTimeout(entry.timerId);
      _store.delete(key);
    }
  }
}

module.exports = { get, set, clear, touch, cleanup, WORKFLOW_EXPIRE_MS };

/**
 * PendingStore — generic auto-expiring key-value store for pending confirmations.
 *
 * Replaces raw Map + setTimeout patterns used for pendingPremiumData,
 * pendingEditConfirm, pendingBulkEdit, pendingDelete, pendingFieldEdit, etc.
 *
 * Interface:
 *   - store.get(key)          → value | undefined
 *   - store.set(key, value)   → void (auto-expires after ttlMs)
 *   - store.delete(key)       → void
 *   - store.has(key)          → boolean
 *   - store.cleanup()         → void (remove expired entries — safety net)
 *
 * @param {number} [ttlMs=300000]  Time-to-live in milliseconds (default: 5 minutes)
 */
class PendingStore {
  constructor(ttlMs = 5 * 60 * 1000) {
    this._ttlMs = ttlMs;
    this._store = new Map(); // key → { value, timerId, createdAt }
  }

  get(key) {
    const entry = this._store.get(key);
    return entry ? entry.value : undefined;
  }

  set(key, value) {
    // Clear existing entry if overwriting
    const existing = this._store.get(key);
    if (existing) clearTimeout(existing.timerId);

    const timerId = setTimeout(() => this._store.delete(key), this._ttlMs);
    this._store.set(key, { value, timerId, createdAt: Date.now() });
  }

  delete(key) {
    const entry = this._store.get(key);
    if (entry) clearTimeout(entry.timerId);
    this._store.delete(key);
  }

  has(key) {
    return this._store.has(key);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this._store) {
      if (now - entry.createdAt > this._ttlMs) {
        clearTimeout(entry.timerId);
        this._store.delete(key);
      }
    }
  }

  get size() {
    return this._store.size;
  }
}

module.exports.PendingStore = PendingStore;

'use strict';

/**
 * auditLog — secure audit logging utility for suspected.dev
 *
 * Writes JSON-line entries to backend/logs/admin_audit.log.
 * The file is created on module load with 0600 permissions
 * (owner read/write only) and is never rotated automatically.
 *
 * Exported API:
 *   writeAuditLog(entry)  — append a JSON audit entry (async, silent on error)
 *   hashIp(ip)            — sha256 hash an IP for privacy-preserving logging
 *   AUDIT_LOG_PATH        — absolute path to the log file
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const AUDIT_LOG_DIR  = path.join(__dirname, 'logs');
const AUDIT_LOG_PATH = path.join(AUDIT_LOG_DIR, 'admin_audit.log');

// Ensure the logs directory and log file exist with restrictive permissions
(function ensureLogFile() {
  try {
    if (!fs.existsSync(AUDIT_LOG_DIR)) {
      fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    }
    if (!fs.existsSync(AUDIT_LOG_PATH)) {
      fs.writeFileSync(AUDIT_LOG_PATH, '', { mode: 0o600 });
    } else {
      // Enforce 0600 on every startup (best-effort; may be a no-op on some platforms)
      try { fs.chmodSync(AUDIT_LOG_PATH, 0o600); } catch { /* ignore */ }
    }
  } catch (err) {
    process.stderr.write(`[auditLog] setup failed: ${err.message}\n`);
  }
}());

/**
 * Hash an IP address for privacy-preserving logging.
 * Returns undefined for falsy input so the field is omitted from non-API sources.
 *
 * @param {string} ip
 * @returns {string|undefined} 'sha256-<64-hex-chars>' or undefined
 */
function hashIp(ip) {
  if (!ip || typeof ip !== 'string') return undefined;
  return 'sha256-' + crypto.createHash('sha256').update(ip).digest('hex');
}

/**
 * Append a JSON audit log entry to admin_audit.log.
 * Never throws — write errors are reported to stderr only.
 *
 * @param {object} entry
 */
function writeAuditLog(entry) {
  const line = JSON.stringify(entry) + '\n';
  fs.appendFile(AUDIT_LOG_PATH, line, (err) => {
    if (err) process.stderr.write(`[auditLog] write failed: ${err.message}\n`);
  });
}

module.exports = { writeAuditLog, hashIp, AUDIT_LOG_PATH };

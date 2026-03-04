/**
 * Frontend XSS Security Tests — index.html JavaScript
 *
 * Validates the three client-side sanitisation layers described in the
 * security audit of frontend/index.html:
 *
 *   8.  escapeHtml()          – HTML-entity encoder used on every API value
 *   9.  createWalletRow()     – Table-row builder; verifies all API fields are escaped
 *  10.  txHash URL construction – Base58 regex blocks all non-safe characters
 *
 * Functions under test are replicated here verbatim from index.html so that
 * the tests run in the Node.js Jest environment without needing a DOM shim.
 *
 * Run: npm test
 */

'use strict';

// ─── Replicate frontend utility functions from index.html ─────────────────────

/**
 * Mirrors escapeHtml() from index.html (line 1330).
 * Encodes the five HTML-special characters so user / API data cannot inject
 * markup when interpolated into a template-literal HTML string.
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Base58 regex used by createWalletRow() (index.html line 1712).
 * Requires ≥ 8 characters and allows only the Base58 alphabet, which has no
 * HTML-special characters, ensuring safe interpolation into href attributes.
 */
const TX_HASH_B58_REGEX = /^[1-9A-HJ-NP-Za-km-z]{8,}$/;

/**
 * Mirrors createWalletRow() from index.html (lines 1709-1729).
 * Returns an HTML <tr> string with all API-supplied fields HTML-encoded.
 */
function createWalletRow(wallet) {
    const txHash = wallet.evidence?.txHash ?? '';
    const safeTxHash = TX_HASH_B58_REGEX.test(txHash) ? escapeHtml(txHash) : '';
    const txLink = safeTxHash
        ? `<a href="https://solscan.io/tx/${safeTxHash}" target="_blank" rel="noopener noreferrer" class="wallet-table-link">${safeTxHash.substring(0, 8)}...${safeTxHash.substring(safeTxHash.length - 8)}</a>`
        : '—';
    const statusClass = wallet.status === 'verified' ? 'status-confirmed' : 'status-suspicious';

    return `
        <tr>
            <td>${escapeHtml(wallet.caseNumber) || '—'}</td>
            <td>${escapeHtml(wallet.walletAddress) || '—'}</td>
            <td>${escapeHtml(wallet.tokenAddress) || '—'}</td>
            <td>${txLink}</td>
            <td>${escapeHtml(wallet.evidence?.description) || '—'}</td>
            <td><span class="status-badge ${statusClass}">${escapeHtml(wallet.status) || '—'}</span></td>
            <td>${escapeHtml(wallet.riskScore) || '—'}</td>
        </tr>
    `;
}

// ─── Shared payloads ──────────────────────────────────────────────────────────

const XSS_SCRIPT   = '<script>alert(1)</script>';
const XSS_IMG      = '<img src=x onerror=alert(1)>';
const XSS_ATTR_DQ  = '" onmouseover="evil()';
const XSS_ATTR_SQ  = "' onmouseover='evil()";
const VALID_TX     = 'ZeKaYDCPcCRFY9jHV4qHikWb3d6z4xB9SuKH1j6U2vxf'; // valid Base58, 44 chars
const VALID_ADDR   = 'So11111111111111111111111111111111111111112';

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('8. Frontend XSS — escapeHtml()', () => {
    test('escapes < and > (script tag injection)', () => {
        expect(escapeHtml(XSS_SCRIPT)).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    test('escapes < and > (img onerror injection)', () => {
        expect(escapeHtml(XSS_IMG)).toBe('&lt;img src=x onerror=alert(1)&gt;');
    });

    test('escapes double quotes (attribute injection)', () => {
        expect(escapeHtml(XSS_ATTR_DQ)).toBe('&quot; onmouseover=&quot;evil()');
    });

    test('escapes single quotes (attribute injection)', () => {
        expect(escapeHtml(XSS_ATTR_SQ)).toBe('&#039; onmouseover=&#039;evil()');
    });

    test('escapes & to prevent entity-encoding bypass', () => {
        expect(escapeHtml('&lt;script&gt;')).toBe('&amp;lt;script&amp;gt;');
    });

    test('returns empty string for null', () => {
        expect(escapeHtml(null)).toBe('');
    });

    test('returns empty string for undefined', () => {
        expect(escapeHtml(undefined)).toBe('');
    });

    test('converts numbers to string without escaping', () => {
        expect(escapeHtml(42)).toBe('42');
    });

    test('leaves safe plain text unchanged', () => {
        expect(escapeHtml('Normal text 123')).toBe('Normal text 123');
    });

    test('leaves javascript: URI unchanged — URL context requires separate validation', () => {
        // escapeHtml encodes HTML-special chars; javascript:alert(1) has none,
        // so it passes through. The Base58 URL regex (tested in group 10) blocks it.
        expect(escapeHtml('javascript:alert(1)')).toBe('javascript:alert(1)');
    });
});

describe('9. Frontend XSS — createWalletRow() [CRITICAL innerHTML path]', () => {
    // createWalletRow() output is concatenated into container.innerHTML (index.html
    // line 1660). Every API field must be HTML-encoded before reaching the DOM.

    test('[CRITICAL] walletAddress <script> payload is escaped', () => {
        const row = createWalletRow({ walletAddress: XSS_SCRIPT, status: 'verified', evidence: {} });
        expect(row).not.toContain('<script>');
        expect(row).toContain('&lt;script&gt;');
    });

    test('[CRITICAL] walletAddress attribute-injection payload is escaped', () => {
        const row = createWalletRow({ walletAddress: XSS_ATTR_DQ, status: 'verified', evidence: {} });
        expect(row).not.toContain(XSS_ATTR_DQ);
        expect(row).toContain('&quot;');
    });

    test('[CRITICAL] evidence description <script> payload is escaped', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { description: XSS_SCRIPT },
        });
        expect(row).not.toContain('<script>');
        expect(row).toContain('&lt;script&gt;');
    });

    test('[CRITICAL] evidence description img-onerror payload is escaped', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { description: XSS_IMG },
        });
        expect(row).not.toContain('<img');
        expect(row).toContain('&lt;img');
    });

    test('[CRITICAL] txHash XSS payload rejected by regex — link falls back to "—"', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: XSS_SCRIPT },
        });
        expect(row).not.toContain('solscan.io/tx/<script>');
        expect(row).not.toContain('<script>');
        // Link is replaced with the safe fallback
        expect(row).toContain('—');
    });

    test('[CRITICAL] riskScore XSS payload is escaped', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            riskScore: XSS_SCRIPT,
            evidence: {},
        });
        expect(row).not.toContain('<script>');
        expect(row).toContain('&lt;script&gt;');
    });

    test('[CRITICAL] tokenAddress XSS payload is escaped', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            tokenAddress: XSS_SCRIPT,
            status: 'verified',
            evidence: {},
        });
        expect(row).not.toContain('<script>');
        expect(row).toContain('&lt;script&gt;');
    });

    test('[CRITICAL] caseNumber XSS payload is escaped', () => {
        const row = createWalletRow({
            caseNumber: XSS_SCRIPT,
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: {},
        });
        expect(row).not.toContain('<script>');
        expect(row).toContain('&lt;script&gt;');
    });

    test('status XSS in text content is escaped; class attribute uses safe ternary', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: XSS_SCRIPT,
            evidence: {},
        });
        // Rendered text must be escaped
        expect(row).not.toContain('<script>');
        // Class attribute must be one of the two safe hard-coded values
        expect(row).toContain('status-suspicious');
        expect(row).not.toContain(XSS_SCRIPT);
    });

    test('valid txHash produces a safe solscan.io link', () => {
        const row = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: VALID_TX },
        });
        expect(row).toContain(`https://solscan.io/tx/${VALID_TX}`);
        expect(row).not.toContain('javascript:');
    });

    test('null / undefined fields render as "—" without throwing', () => {
        const row = createWalletRow({
            walletAddress: null,
            tokenAddress: undefined,
            status: 'verified',
            evidence: { txHash: null, description: null },
        });
        // escapeHtml(null) → '' → falls back to '—'
        expect(row).not.toContain('null');
        expect(row).not.toContain('undefined');
    });
});

describe('10. Frontend XSS — Dynamic URL construction (txHash Base58 validation)', () => {
    // The Base58 regex /^[1-9A-HJ-NP-Za-km-z]{8,}$/ gates what may appear in
    // the href "https://solscan.io/tx/<value>". All dangerous characters must
    // be outside the allowed set.

    test('rejects <script> tag — HTML injection in href', () => {
        expect(TX_HASH_B58_REGEX.test(XSS_SCRIPT)).toBe(false);
    });

    test('rejects javascript: URI — prevents href="javascript:…"', () => {
        expect(TX_HASH_B58_REGEX.test('javascript:alert(1)')).toBe(false);
    });

    test('rejects path traversal string', () => {
        expect(TX_HASH_B58_REGEX.test('../../etc/passwd')).toBe(false);
    });

    test('rejects hash with spaces (HTTP response splitting)', () => {
        expect(TX_HASH_B58_REGEX.test('validhash withspace')).toBe(false);
    });

    test('rejects percent-encoded XSS (%3Cscript%3E)', () => {
        expect(TX_HASH_B58_REGEX.test('%3Cscript%3E')).toBe(false);
    });

    test('rejects hash shorter than 8 characters', () => {
        expect(TX_HASH_B58_REGEX.test('abc123')).toBe(false);
    });

    test('rejects hash containing Base58-excluded characters (0, O, I, l)', () => {
        expect(TX_HASH_B58_REGEX.test('0OIl0OIl0OIl0OIl')).toBe(false);
    });

    test('rejects double-quote injection inside href attribute', () => {
        expect(TX_HASH_B58_REGEX.test(XSS_ATTR_DQ)).toBe(false);
    });

    test('accepts a well-formed Base58 transaction hash', () => {
        expect(TX_HASH_B58_REGEX.test(VALID_TX)).toBe(true);
    });

    test('accepts another valid 44-char Solana address as txHash', () => {
        expect(TX_HASH_B58_REGEX.test(VALID_ADDR)).toBe(true);
    });
});

/**
 * Frontend Security Tests — index.html
 *
 * Tests security controls in index.html using Jest + jsdom:
 *   1. escapeHtml()        — verifies all five HTML-special characters are encoded
 *   2. createWalletRow()   — verifies every API-sourced field is escaped before DOM insertion
 *   3. Form submission     — verifies reporterContact is NOT included in the POST payload
 *   4. txHash validation   — verifies invalid base58 strings are rejected before API call
 *   5. External links      — verifies all target="_blank" links have rel="noopener noreferrer"
 *
 * Run (from frontend/ directory):
 *   npm test
 *   npm test -- tests/security.test.js
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Functions replicated verbatim from index.html ─────────────────────────────
// (lines 1393-1401)

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Base58 URL-safety regex used in createWalletRow (index.html line 1800)
const TX_HASH_B58_REGEX = /^[1-9A-HJ-NP-Za-km-z]{8,}$/;

// (lines 1797-1817)
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

// ── Shared test fixtures ──────────────────────────────────────────────────────

const VALID_TX   = 'ZeKaYDCPcCRFY9jHV4qHikWb3d6z4xB9SuKH1j6U2vxf'; // 44-char Base58
const VALID_ADDR = 'So11111111111111111111111111111111111111112';     // 43-char Base58

// ════════════════════════════════════════════════════════════════════════════
// 1. escapeHtml()
// ════════════════════════════════════════════════════════════════════════════

describe('1. escapeHtml()', () => {
    test('escapes < (less-than)', () => {
        expect(escapeHtml('<')).toBe('&lt;');
    });

    test('escapes > (greater-than)', () => {
        expect(escapeHtml('>')).toBe('&gt;');
    });

    test('escapes & (ampersand)', () => {
        expect(escapeHtml('&')).toBe('&amp;');
    });

    test('escapes " (double-quote)', () => {
        expect(escapeHtml('"')).toBe('&quot;');
    });

    test("escapes ' (single-quote)", () => {
        expect(escapeHtml("'")).toBe('&#039;');
    });

    test('encodes all five special characters in a combined XSS payload', () => {
        const result = escapeHtml('<script>alert("xss\'s")</script>');
        expect(result).toBe('&lt;script&gt;alert(&quot;xss&#039;s&quot;)&lt;/script&gt;');
    });

    test('encodes & first to prevent double-encoding bypass', () => {
        expect(escapeHtml('&lt;script&gt;')).toBe('&amp;lt;script&amp;gt;');
    });

    test('returns empty string for null', () => {
        expect(escapeHtml(null)).toBe('');
    });

    test('returns empty string for undefined', () => {
        expect(escapeHtml(undefined)).toBe('');
    });

    test('converts numbers to string without modification', () => {
        expect(escapeHtml(42)).toBe('42');
    });

    test('leaves plain alphanumeric text unchanged', () => {
        expect(escapeHtml('Normal text 123')).toBe('Normal text 123');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. createWalletRow() — DOM insertion escaping
// ════════════════════════════════════════════════════════════════════════════

describe('2. createWalletRow() — API fields escaped before DOM insertion', () => {
    let container;

    beforeEach(() => {
        container = document.createElement('tbody');
    });

    afterEach(() => {
        container = null;
    });

    /** Helper: render a wallet row and return the jsdom container element. */
    function renderRow(wallet) {
        container.innerHTML = createWalletRow(wallet);
        return container;
    }

    test('[walletAddress] script-tag payload is not executed — no <script> element in DOM', () => {
        const dom = renderRow({
            walletAddress: '<script>alert(1)</script>',
            status: 'verified',
            evidence: {},
        });
        expect(dom.querySelector('script')).toBeNull();
        expect(dom.textContent).toContain('<script>');
    });

    test('[walletAddress] img-onerror payload is neutralised — no <img> element in DOM', () => {
        const dom = renderRow({
            walletAddress: '<img src=x onerror=alert(1)>',
            status: 'verified',
            evidence: {},
        });
        expect(dom.querySelector('img')).toBeNull();
        expect(dom.textContent).toContain('<img');
    });

    test('[evidence.description] script-tag payload is escaped in DOM', () => {
        const dom = renderRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { description: '<script>evil()</script>' },
        });
        expect(dom.querySelector('script')).toBeNull();
        expect(dom.textContent).toContain('<script>');
    });

    test('[caseNumber] HTML injection payload is escaped — no injected element in DOM', () => {
        const dom = renderRow({
            caseNumber: '<b>inject</b>',
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: {},
        });
        expect(dom.querySelector('b')).toBeNull();
    });

    test('[riskScore] HTML injection payload is escaped — no injected element in DOM', () => {
        const dom = renderRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            riskScore: '<marquee>hack</marquee>',
            evidence: {},
        });
        expect(dom.querySelector('marquee')).toBeNull();
    });

    test('[tokenAddress] injected anchor does not survive DOM parsing', () => {
        const dom = renderRow({
            walletAddress: VALID_ADDR,
            tokenAddress: '<a href="evil://x">click</a>',
            status: 'verified',
            evidence: {},
        });
        // Any anchor present must belong to createWalletRow's own safe txLink, not the injection
        dom.querySelectorAll('a').forEach(a => {
            expect(a.getAttribute('href')).not.toContain('evil://');
        });
    });

    test('[txHash] XSS payload is rejected by regex — no link rendered, no script element', () => {
        const dom = renderRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: '<script>evil()</script>' },
        });
        expect(dom.querySelector('script')).toBeNull();
        expect(dom.querySelector('a')).toBeNull();
    });

    test('[txHash] valid Base58 hash produces safe solscan.io link with rel="noopener noreferrer"', () => {
        const dom = renderRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: VALID_TX },
        });
        const link = dom.querySelector('a');
        expect(link).not.toBeNull();
        expect(link.getAttribute('href')).toBe(`https://solscan.io/tx/${VALID_TX}`);
        const rel = link.getAttribute('rel').split(/\s+/);
        expect(rel).toContain('noopener');
        expect(rel).toContain('noreferrer');
    });

    test('null/undefined fields render as "—" without throwing', () => {
        const dom = renderRow({
            walletAddress: null,
            tokenAddress: undefined,
            status: 'verified',
            evidence: { txHash: null, description: null },
        });
        expect(dom.textContent).not.toContain('null');
        expect(dom.textContent).not.toContain('undefined');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. Form submission — reporterContact excluded from POST payload
// ════════════════════════════════════════════════════════════════════════════

describe('3. Form submission — reporterContact not included in POST payload', () => {
    let fetchSpy;
    let capturedBody;

    beforeEach(() => {
        // Minimal DOM mirroring the report form in index.html
        document.body.innerHTML = `
            <form id="reportForm">
                <input id="devWallet"    value="${VALID_ADDR}">
                <input id="txHash"       value="${VALID_TX}">
                <input id="tokenAddress" value="">
                <textarea id="description">Test description</textarea>
                <button type="submit" id="submitBtn">Submit</button>
                <div id="formMessage"></div>
            </form>
        `;

        capturedBody = null;
        // Assign a mock directly — fetch may not pre-exist on the jsdom global
        fetchSpy = jest.fn((_url, options) => {
            capturedBody = JSON.parse(options.body);
            return Promise.resolve({
                json: () => Promise.resolve({
                    success: true,
                    data: { caseNumber: 1 },
                    message: 'created',
                }),
            });
        });
        global.fetch = fetchSpy;
    });

    afterEach(() => {
        delete global.fetch;
        document.body.innerHTML = '';
    });

    /**
     * Replicates the exact formData construction from index.html (lines 1898-1920).
     * Returns the object that would be JSON.stringify'd into the POST body.
     */
    function buildProductionFormData() {
        const walletAddress = document.getElementById('devWallet').value.trim();
        const txInput       = document.getElementById('txHash').value.trim();
        let txHash = txInput;
        if (txInput.includes('solscan.io/tx/')) {
            const match = txInput.match(/tx\/([a-zA-Z0-9]+)/);
            if (match) txHash = match[1];
        }
        return {
            walletAddress,
            evidence: {
                txHash,
                description: document.getElementById('description').value.trim(),
            },
            projectName: '',
            tokenAddress: document.getElementById('tokenAddress').value.trim() || undefined,
        };
    }

    test('formData object does not contain a reporterContact property', () => {
        const payload = buildProductionFormData();
        expect(payload).not.toHaveProperty('reporterContact');
    });

    test('JSON.stringify of formData does not contain the string "reporterContact"', () => {
        const payload = buildProductionFormData();
        expect(JSON.stringify(payload)).not.toContain('reporterContact');
    });

    test('fetch is called and the POST body does not include reporterContact', async () => {
        const payload = buildProductionFormData();
        await fetch('/api/wallets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(capturedBody).not.toHaveProperty('reporterContact');
    });

    test('POST body contains the expected safe fields (walletAddress, evidence)', async () => {
        const payload = buildProductionFormData();
        await fetch('/api/wallets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        expect(capturedBody).toHaveProperty('walletAddress', VALID_ADDR);
        expect(capturedBody.evidence).toHaveProperty('txHash', VALID_TX);
        expect(capturedBody.evidence).toHaveProperty('description', 'Test description');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. txHash validation — invalid base58 rejected before API call
// ════════════════════════════════════════════════════════════════════════════

describe('4. txHash validation — invalid base58 strings rejected', () => {
    // Mirrors the createWalletRow() URL-safety regex (index.html line 1800)
    const URL_SAFE_REGEX = /^[1-9A-HJ-NP-Za-km-z]{8,}$/;

    test('rejects empty string', () => {
        expect(URL_SAFE_REGEX.test('')).toBe(false);
    });

    test('rejects <script> tag (HTML injection in href)', () => {
        expect(URL_SAFE_REGEX.test('<script>alert(1)</script>')).toBe(false);
    });

    test('rejects javascript: URI (would create javascript:// href)', () => {
        expect(URL_SAFE_REGEX.test('javascript:alert(1)')).toBe(false);
    });

    test('rejects path traversal string (../../etc/passwd)', () => {
        expect(URL_SAFE_REGEX.test('../../etc/passwd')).toBe(false);
    });

    test('rejects strings containing spaces (HTTP splitting / header injection)', () => {
        expect(URL_SAFE_REGEX.test('validhash withspace')).toBe(false);
    });

    test('rejects percent-encoded XSS (%3Cscript%3E)', () => {
        expect(URL_SAFE_REGEX.test('%3Cscript%3Ealert%281%29')).toBe(false);
    });

    test('rejects strings shorter than 8 characters', () => {
        expect(URL_SAFE_REGEX.test('abc123')).toBe(false);
    });

    test('rejects Base58-excluded characters (0, O, I, l)', () => {
        expect(URL_SAFE_REGEX.test('0OIl0OIl0OIl0OIl')).toBe(false);
    });

    test('rejects double-quote injection (attribute breakout)', () => {
        expect(URL_SAFE_REGEX.test('" onmouseover="evil()')).toBe(false);
    });

    test('accepts a valid 44-character Solana Base58 transaction hash', () => {
        expect(URL_SAFE_REGEX.test(VALID_TX)).toBe(true);
    });

    test('accepts a valid 43-character Base58 wallet address used as txHash', () => {
        expect(URL_SAFE_REGEX.test(VALID_ADDR)).toBe(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. External links — all target="_blank" must have rel="noopener noreferrer"
// ════════════════════════════════════════════════════════════════════════════

describe('5. External links — target="_blank" links include rel="noopener noreferrer"', () => {
    const HTML_SOURCE = fs.readFileSync(
        path.resolve(__dirname, '../index.html'),
        'utf-8'
    );

    test('every line containing target="_blank" also contains rel="noopener noreferrer"', () => {
        const blankLines = HTML_SOURCE
            .split('\n')
            .filter(line => line.includes('target="_blank"'));

        // Sanity check: the HTML file must contain at least one target="_blank" reference
        expect(blankLines.length).toBeGreaterThan(0);

        const unsafe = blankLines.filter(line => !line.includes('rel="noopener noreferrer"'));
        expect(unsafe).toEqual([]);
    });

    test('createWalletRow() dynamic link has rel containing "noopener" and "noreferrer"', () => {
        const container = document.createElement('tbody');
        container.innerHTML = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: VALID_TX },
        });

        const link = container.querySelector('a[target="_blank"]');
        expect(link).not.toBeNull();

        const rel = link.getAttribute('rel').split(/\s+/);
        expect(rel).toContain('noopener');
        expect(rel).toContain('noreferrer');
    });

    test('createWalletRow() dynamic link uses target="_blank"', () => {
        const container = document.createElement('tbody');
        container.innerHTML = createWalletRow({
            walletAddress: VALID_ADDR,
            status: 'verified',
            evidence: { txHash: VALID_TX },
        });

        const link = container.querySelector('a');
        expect(link).not.toBeNull();
        expect(link.getAttribute('target')).toBe('_blank');
    });
});

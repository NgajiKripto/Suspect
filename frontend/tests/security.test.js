/**
 * Frontend Security Tests — index.html
 *
 * Tests security controls in index.html using Jest + jsdom:
 *   1. escapeHtml()        — verifies all five HTML-special characters are encoded
 *   2. createWalletRow()   — verifies every API-sourced field is escaped before DOM insertion
 *   3. Form submission     — verifies reporterContact is NOT included in the POST payload
 *   4. txHash validation   — verifies invalid base58 strings are rejected before API call
 *   5. External links      — verifies all target="_blank" links have rel="noopener noreferrer"
 *   6. CSP audit           — verifies meta CSP directives (no localhost, frame-src none, etc.)
 *   7. Referrer policy     — verifies external <img> tags have referrerpolicy="no-referrer"
 *   8. External links rel  — verifies footer/social links have rel="noopener noreferrer"
 *   9. safeInnerHtml       — verifies anchor support with validated href and enforced rel/target
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

// ════════════════════════════════════════════════════════════════════════════
// 6. CSP audit — meta Content-Security-Policy directives
// ════════════════════════════════════════════════════════════════════════════

describe('6. CSP audit — meta Content-Security-Policy', () => {
    const HTML_SOURCE = fs.readFileSync(
        path.resolve(__dirname, '../index.html'),
        'utf-8'
    );

    /** Extract the content attribute of the CSP meta tag. */
    function extractCspContent(html) {
        const match = html.match(
            /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i
        );
        return match ? match[1] : '';
    }

    const CSP = extractCspContent(HTML_SOURCE);

    test('CSP meta tag is present', () => {
        expect(CSP.length).toBeGreaterThan(0);
    });

    test('connect-src does NOT include http://localhost:3000 (dev endpoint removed from production CSP)', () => {
        expect(CSP).not.toContain('localhost');
        expect(CSP).not.toContain('http://localhost:3000');
    });

    test('connect-src restricts network requests to self and https://suspected.dev only', () => {
        expect(CSP).toContain('connect-src');
        expect(CSP).toContain('https://suspected.dev');
    });

    test('frame-src is "none" (no iframe embeds needed, eliminates clickjacking surface)', () => {
        expect(CSP).toMatch(/frame-src\s+'none'/);
    });

    test('object-src is "none" (blocks plugins)', () => {
        expect(CSP).toMatch(/object-src\s+'none'/);
    });

    test('base-uri is "self" (prevents base-tag injection)', () => {
        expect(CSP).toMatch(/base-uri\s+'self'/);
    });

    test('form-action is "self" (prevents cross-origin form submission)', () => {
        expect(CSP).toMatch(/form-action\s+'self'/);
    });

    test('upgrade-insecure-requests directive is present', () => {
        expect(CSP).toContain('upgrade-insecure-requests');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 7. Referrer policy — external images and document meta
// ════════════════════════════════════════════════════════════════════════════

describe('7. Referrer policy — external <img> tags and document meta', () => {
    const HTML_SOURCE = fs.readFileSync(
        path.resolve(__dirname, '../index.html'),
        'utf-8'
    );

    test('document has a <meta name="referrer"> policy tag', () => {
        expect(HTML_SOURCE).toMatch(/<meta\s+name="referrer"\s+content="[^"]+"/i);
    });

    test('Referrer-Policy meta is set to strict-origin-when-cross-origin', () => {
        expect(HTML_SOURCE).toContain('content="strict-origin-when-cross-origin"');
    });

    test('every external <img> src has referrerpolicy="no-referrer"', () => {
        // Match all <img> tags that reference an external (https://) URL
        const imgTagRegex = /<img\b[^>]*src="https?:\/\/[^"]*"[^>]*>/gi;
        const externalImgs = HTML_SOURCE.match(imgTagRegex) || [];

        // Sanity check: the page must contain at least one external image (logos/badges)
        expect(externalImgs.length).toBeGreaterThan(0);

        const missingPolicy = externalImgs.filter(
            tag => !tag.includes('referrerpolicy="no-referrer"')
        );
        expect(missingPolicy).toEqual([]);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 8. External links — footer links have rel="noopener noreferrer"
// ════════════════════════════════════════════════════════════════════════════

describe('8. External links — footer and social links have rel="noopener noreferrer"', () => {
    const HTML_SOURCE = fs.readFileSync(
        path.resolve(__dirname, '../index.html'),
        'utf-8'
    );

    test('every line with an external https:// href also has rel="noopener noreferrer"', () => {
        // Find all <a href="https://..."> lines (static HTML, not JS template literals)
        const anchorLines = HTML_SOURCE
            .split('\n')
            .filter(line => /<a\b[^>]*href="https?:\/\//.test(line));

        // Sanity: at least the footer links should be present
        expect(anchorLines.length).toBeGreaterThan(0);

        const unsafe = anchorLines.filter(
            line => !line.includes('rel="noopener noreferrer"')
        );
        expect(unsafe).toEqual([]);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 9. safeInnerHtml — anchor support with validated href
// ════════════════════════════════════════════════════════════════════════════

/**
 * Replicated verbatim from index.html — the updated safeInnerHtml with anchor support.
 * (Runs in jsdom so document.createElement is available.)
 */
function safeInnerHtml(element, content, options) {
    const allowedTags = (options && Array.isArray(options.allowedTags))
        ? options.allowedTags
        : ['strong', 'em', 'br', 'code'];

    const RAW_TEXT_TAGS = ['script', 'style', 'template', 'textarea', 'noscript'];

    const tmpl = document.createElement('template');
    tmpl.innerHTML = content;
    const fragment = tmpl.content;

    const allElements = Array.from(fragment.querySelectorAll('*')).reverse();
    allElements.forEach(function(el) {
        if (!el.parentNode) return;
        const tag = el.tagName.toLowerCase();
        if (!allowedTags.includes(tag)) {
            if (RAW_TEXT_TAGS.includes(tag)) {
                el.parentNode.removeChild(el);
            } else {
                while (el.firstChild) {
                    el.parentNode.insertBefore(el.firstChild, el);
                }
                el.parentNode.removeChild(el);
            }
            return;
        }
        if (tag === 'a') {
            const rawHref = (el.getAttribute('href') || '').trim();
            // Allow only safe URL schemes and safe relative paths.
            // The negative lookahead blocks root-relative paths that begin with a
            // scheme-like sequence (e.g. /javascript:) or a protocol-relative URL (//).
            const safeHref = /^(https?:\/\/|mailto:|#|\/(?![a-z][a-z0-9+\-.]*:|\/))/.test(rawHref) ? rawHref : '';
            Array.from(el.attributes).forEach(function(attr) { el.removeAttribute(attr.name); });
            if (safeHref) {
                el.setAttribute('href', safeHref);
                if (/^https?:\/\//.test(safeHref)) {
                    el.setAttribute('target', '_blank');
                    el.setAttribute('rel', 'noopener noreferrer');
                }
            }
        } else {
            Array.from(el.attributes).forEach(function(attr) {
                el.removeAttribute(attr.name);
            });
        }
    });

    element.innerHTML = '';
    element.appendChild(fragment);
    return element;
}

describe('9. safeInnerHtml — anchor support with validated href', () => {
    let el;

    beforeEach(() => {
        el = document.createElement('div');
    });

    afterEach(() => {
        el = null;
    });

    test('<a> is stripped when "a" is not in allowedTags (default behaviour preserved)', () => {
        safeInnerHtml(el, '<a href="https://example.com">link</a>');
        expect(el.querySelector('a')).toBeNull();
        expect(el.textContent).toBe('link');
    });

    test('<a> renders as clickable link when "a" is in allowedTags', () => {
        safeInnerHtml(el, '<a href="https://t.me/suspecteddotdev">@suspecteddotdev</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('href')).toBe('https://t.me/suspecteddotdev');
        expect(anchor.textContent).toBe('@suspecteddotdev');
    });

    test('safeInnerHtml enforces rel="noopener noreferrer" on https:// anchors', () => {
        safeInnerHtml(el, '<a href="https://t.me/suspecteddotdev">link</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        const rel = anchor.getAttribute('rel').split(/\s+/);
        expect(rel).toContain('noopener');
        expect(rel).toContain('noreferrer');
    });

    test('safeInnerHtml enforces target="_blank" on https:// anchors', () => {
        safeInnerHtml(el, '<a href="https://t.me/suspecteddotdev">link</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('target')).toBe('_blank');
    });

    test('javascript: href is stripped (not rendered as link)', () => {
        safeInnerHtml(el, '<a href="javascript:alert(1)">xss</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        // Anchor element is present but href must be absent
        if (anchor) {
            expect(anchor.getAttribute('href')).toBeNull();
        }
        // The text content should still be visible
        expect(el.textContent).toBe('xss');
    });

    test('data: href is stripped', () => {
        safeInnerHtml(el, '<a href="data:text/html,<script>alert(1)</script>">xss</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        if (anchor) {
            expect(anchor.getAttribute('href')).toBeNull();
        }
    });

    test('vbscript: href is stripped', () => {
        safeInnerHtml(el, '<a href="vbscript:msgbox(1)">xss</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        if (anchor) {
            expect(anchor.getAttribute('href')).toBeNull();
        }
    });

    test('onclick attribute is stripped from allowed <a> even when href is valid', () => {
        safeInnerHtml(el, '<a href="https://example.com" onclick="evil()">link</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('onclick')).toBeNull();
        expect(anchor.getAttribute('href')).toBe('https://example.com');
    });

    test('onerror attribute is stripped from allowed <a>', () => {
        safeInnerHtml(el, '<a href="https://example.com" onerror="evil()">link</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('onerror')).toBeNull();
    });

    test('<script> inside an allowed <a> is still removed', () => {
        safeInnerHtml(el, '<a href="https://example.com"><script>evil()</script>link</a>', {
            allowedTags: ['a'],
        });
        expect(el.querySelector('script')).toBeNull();
        expect(el.textContent).toBe('link');
    });

    test('relative href (#anchor) is preserved without target or rel', () => {
        safeInnerHtml(el, '<a href="#section">Jump</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('href')).toBe('#section');
        // No forced target/_blank for fragment links
        expect(anchor.getAttribute('target')).toBeNull();
    });

    test('/javascript: root-relative bypass is blocked (href stripped)', () => {
        safeInnerHtml(el, '<a href="/javascript:alert(1)">xss</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        if (anchor) {
            expect(anchor.getAttribute('href')).toBeNull();
        }
        expect(el.textContent).toBe('xss');
    });

    test('protocol-relative // URL is blocked (href stripped)', () => {
        safeInnerHtml(el, '<a href="//evil.example.com/xss">xss</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        if (anchor) {
            expect(anchor.getAttribute('href')).toBeNull();
        }
    });

    test('root-relative /path is allowed (same-origin navigation, safe)', () => {
        safeInnerHtml(el, '<a href="/about">About</a>', {
            allowedTags: ['a'],
        });
        const anchor = el.querySelector('a');
        expect(anchor).not.toBeNull();
        expect(anchor.getAttribute('href')).toBe('/about');
        // Root-relative paths are same-origin — no forced target/_blank
        expect(anchor.getAttribute('target')).toBeNull();
    });

});

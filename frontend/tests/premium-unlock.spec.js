/**
 * E2E-style tests for the premium unlock flow — index.html
 *
 * Tests the complete x402 micropayment flow end-to-end using Jest + jsdom,
 * with fetch and x402 SDK fully mocked:
 *
 *   1. Locked premium section  — initial UI state (button, aria, data attrs)
 *   2. Full x402 payment flow  — probe 402 → requestPayment → retry → success
 *   3. XSS protection          — malicious strings in premium fields are escaped
 *   4. Already-authorized path — 200 on probe renders card directly
 *   5. Error states            — SDK unavailable, probe error, payment failure,
 *                                network error
 *   6. Event delegation        — .btn-unlock-premium and .btn-premium-retry clicks
 *
 * Run (from frontend/ directory):
 *   npm test
 *   npm test -- tests/premium-unlock.spec.js
 */

'use strict';

// ── CSS.escape polyfill — not available in Jest/jsdom ────────────────────────
// Implements the CSS.escape spec (https://drafts.csswg.org/cssom/#serialize-an-identifier)
// for use with Base58 wallet addresses.  Handles: NULL replacement, C0/DEL control
// escapes, leading-digit escaping, and backslash-escaping of all other non-identifier chars.
if (typeof global.CSS === 'undefined') {
    global.CSS = {
        escape: function(value) {
            const str = String(value);
            let result = '';
            for (let i = 0; i < str.length; i++) {
                const ch = str[i];
                const code = ch.charCodeAt(0);
                if (code === 0x0000) {
                    result += '\uFFFD';
                } else if ((code >= 0x0001 && code <= 0x001F) || code === 0x007F) {
                    result += '\\' + code.toString(16) + ' ';
                } else if (i === 0 && code >= 0x0030 && code <= 0x0039) {
                    result += '\\3' + ch + ' ';
                } else if (/[^\w-]/.test(ch)) {
                    result += '\\' + ch;
                } else {
                    result += ch;
                }
            }
            return result;
        },
    };
}

// ── Functions replicated verbatim from index.html ─────────────────────────────
// (mirrors escapeHtml at index.html ~line 1393)

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Solana Base58 address regex (mirrors renderPremiumCard in index.html)
const SOLANA_ADDR_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

// API base URL — use a fixed value so tests are independent of window.location
const API_BASE_URL = 'https://suspected.dev/api';

// ── loadX402Sdk — replicated verbatim from index.html ────────────────────────
function loadX402Sdk() {
    return new Promise(function(resolve, reject) {
        if (typeof window.x402 !== 'undefined' && typeof window.x402.requestPayment === 'function') {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdn.x402gateway.io/sdk/v1/x402.min.js';
        script.crossOrigin = 'anonymous';
        script.referrerPolicy = 'no-referrer';
        script.addEventListener('load', resolve);
        script.addEventListener('error', function() {
            reject(new Error('x402 SDK failed to load'));
        });
        document.head.appendChild(script);
    });
}

// ── renderPremiumCard — replicated verbatim from index.html ──────────────────
function renderPremiumCard(walletAddress, data) {
    const detailRow = document.querySelector(
        `.premium-detail-row[data-pu-detail="${CSS.escape(walletAddress)}"]`
    );
    const card = document.querySelector(
        `.premium-card[data-pu-card="${CSS.escape(walletAddress)}"]`
    );
    if (!detailRow || !card) return;

    const pf = data.premiumForensics;
    if (!pf) {
        card.innerHTML =
            '<p style="color:var(--text-muted);font-size:0.85rem;">' +
                'No premium forensic data available for this wallet yet.' +
            '</p>';
        detailRow.classList.add('visible');
        return;
    }

    // Tokens Created — validated addresses become Solscan links
    const tokensHtml = (function() {
        if (!Array.isArray(pf.tokensCreated) || pf.tokensCreated.length === 0) {
            return '<span>\u2014</span>';
        }
        const items = pf.tokensCreated.map(function(addr) {
            const raw = String(addr || '');
            if (SOLANA_ADDR_RE.test(raw)) {
                const safe = escapeHtml(raw);
                return '<li><a class="premium-token-link"' +
                    ` href="https://solscan.io/token/${safe}"` +
                    ' target="_blank" rel="noopener noreferrer">' +
                    safe + '</a></li>';
            }
            return `<li>${escapeHtml(raw)}</li>`;
        });
        return `<ul class="premium-token-list">${items.join('')}</ul>`;
    }());

    // Cross-Project Links — "ADDR:RISK" or plain address; risk badge from allow-list
    const crossLinksHtml = (function() {
        if (!Array.isArray(pf.crossProjectLinks) || pf.crossProjectLinks.length === 0) {
            return '<span>\u2014</span>';
        }
        const RISK_LEVELS = { HIGH: 'risk-badge-high', MEDIUM: 'risk-badge-medium', LOW: 'risk-badge-low' };
        const items = pf.crossProjectLinks.map(function(entry) {
            const parts = String(entry || '').split(':');
            const addrRaw = parts[0] || '';
            const riskKey = (parts[1] || '').toUpperCase();
            const badge = Object.prototype.hasOwnProperty.call(RISK_LEVELS, riskKey)
                ? `<span class="risk-badge ${RISK_LEVELS[riskKey]}">${riskKey}</span>`
                : '';
            if (SOLANA_ADDR_RE.test(addrRaw)) {
                const safe = escapeHtml(addrRaw);
                return '<li><a class="premium-token-link"' +
                    ` href="https://solscan.io/address/${safe}"` +
                    ' target="_blank" rel="noopener noreferrer">' +
                    safe + '</a>' + badge + '</li>';
            }
            return `<li>${escapeHtml(addrRaw)}${badge}</li>`;
        });
        return `<ul class="premium-token-list">${items.join('')}</ul>`;
    }());

    const fields = [
        { label: 'Add Liquidity Value',    html: escapeHtml(pf.addLiquidityValue    || '\u2014') },
        { label: 'Remove Liquidity Value', html: escapeHtml(pf.removeLiquidityValue || '\u2014') },
        { label: 'Wallet Funding',         html: escapeHtml(pf.walletFunding        || '\u2014') },
        { label: 'Tokens Created',         html: tokensHtml },
        { label: 'Forensic Notes',         html: escapeHtml(pf.forensicNotes        || '\u2014') },
        { label: 'Cross-Project Links',    html: crossLinksHtml },
    ];

    const fieldsHtml = fields.map(function(f) {
        return '<div class="premium-card-field">' +
            `<span class="premium-card-label">${f.label}</span>` +
            `<div class="premium-card-value">${f.html}</div>` +
        '</div>';
    }).join('');

    card.innerHTML =
        `<div class="premium-card-header">\ud83d\udcb3 Premium Forensics \u2014 ${escapeHtml(walletAddress)}</div>` +
        `<div class="premium-card-fields">${fieldsHtml}</div>`;

    detailRow.classList.add('visible');
}

// ── unlockPremiumData — replicated verbatim from index.html ──────────────────
async function unlockPremiumData(walletAddress) {
    const puContainer = document.querySelector(
        `.premium-unlock[data-pu-wallet="${CSS.escape(walletAddress)}"]`
    );
    const announcer = document.getElementById('premium-payment-announce');

    function setPuState(html) {
        if (puContainer) puContainer.innerHTML = html;
    }

    function announce(msg) {
        if (!announcer) return;
        announcer.textContent = msg;
        setTimeout(function() { announcer.textContent = ''; }, 4000);
    }

    // Transition to loading state
    setPuState(
        '<div class="premium-unlock-loading">' +
            '<span class="pu-spinner" aria-hidden="true"></span>' +
            ' Processing payment\u2026' +
        '</div>'
    );
    announce('Initiating x402 payment for premium forensic data.');

    try {
        await loadX402Sdk();

        if (typeof window.x402 === 'undefined' || typeof window.x402.requestPayment !== 'function') {
            setPuState(
                '<div class="premium-unlock-error">' +
                    '<span class="premium-unlock-error-msg">\u26a0 x402 SDK unavailable. Please refresh.</span>' +
                '</div>'
            );
            announce('Payment SDK could not be loaded. Please refresh the page.');
            return;
        }

        const endpoint = `${API_BASE_URL}/wallets/${encodeURIComponent(walletAddress)}/premium/access`;

        // Step 1: probe the endpoint — expect a 402 with payment details
        const probeRes = await fetch(endpoint, { method: 'POST' });

        let paymentToken = null;

        if (probeRes.status === 402) {
            const payReq = await probeRes.json().catch(function() { return {}; });
            const requiredAmount = typeof payReq.requiredAmountUSD === 'number'
                ? payReq.requiredAmountUSD
                : 0.11;

            announce('Payment required. Opening x402 payment dialog.');
            paymentToken = await window.x402.requestPayment({
                amount:    requiredAmount,
                currency:  'USD',
                recipient: 'suspected.dev',
                memo:      `Premium forensic data: ${walletAddress}`
            });

        } else if (probeRes.ok) {
            // Payment not required — use the direct response
            const data = await probeRes.json();
            renderPremiumCard(walletAddress, data);
            setPuState('<div class="premium-unlock-success">\u2713 Unlocked \u2014 see below</div>');
            announce('Premium forensic data unlocked successfully.');
            return;

        } else {
            const err = await probeRes.json().catch(function() { return {}; });
            const safeMsg = escapeHtml(err.message || 'Unexpected error');
            setPuState(
                '<div class="premium-unlock-error">' +
                    `<span class="premium-unlock-error-msg">\u26a0 ${safeMsg}</span>` +
                    `<button class="btn-premium-retry" data-wallet="${escapeHtml(walletAddress)}">\u21a9 Retry</button>` +
                '</div>'
            );
            announce(`Payment error: ${err.message || 'Unexpected error'}`);
            return;
        }

        // Step 3: retry with the payment token
        announce('Payment confirmed. Fetching premium data\u2026');
        const paidRes = await fetch(endpoint, {
            method:  'POST',
            headers: { 'x402-payment': paymentToken }
        });

        if (!paidRes.ok) {
            const err = await paidRes.json().catch(function() { return {}; });
            const safeMsg = escapeHtml(err.message || 'Verification error');
            setPuState(
                '<div class="premium-unlock-error">' +
                    `<span class="premium-unlock-error-msg">\u26a0 Payment failed: ${safeMsg}</span>` +
                    `<button class="btn-premium-retry" data-wallet="${escapeHtml(walletAddress)}">\u21a9 Retry</button>` +
                '</div>'
            );
            announce(`Payment verification failed: ${err.message || 'Verification error'}`);
            return;
        }

        const data = await paidRes.json();
        renderPremiumCard(walletAddress, data);
        setPuState('<div class="premium-unlock-success">\u2713 Unlocked \u2014 see below</div>');
        announce('Premium forensic data unlocked successfully.');

    } catch (error) {
        const safeMsg = escapeHtml(error.message || 'Unknown error');
        setPuState(
            '<div class="premium-unlock-error">' +
                `<span class="premium-unlock-error-msg">\u26a0 ${safeMsg}</span>` +
                `<button class="btn-premium-retry" data-wallet="${escapeHtml(walletAddress)}">\u21a9 Retry</button>` +
            '</div>'
        );
        announce(`Unlock failed: ${error.message || 'Unknown error'}`);
    }
}

// ── Shared test fixtures ──────────────────────────────────────────────────────

const VALID_ADDR  = 'So11111111111111111111111111111111111111112';   // 43-char Base58
const VALID_ADDR2 = 'ZeKaYDCPcCRFY9jHV4qHikWb3d6z4xB9SuKH1j6U2vxf'; // 44-char Base58

/** Minimal premium forensics payload with all six fields populated. */
const FULL_PREMIUM_DATA = {
    premiumForensics: {
        addLiquidityValue:    '15.5 SOL',
        removeLiquidityValue: '12.3 SOL',
        walletFunding:        'CEX withdrawal — Binance',
        tokensCreated:        [VALID_ADDR2],
        forensicNotes:        'Coordinated rug-pull pattern observed across three pools.',
        crossProjectLinks:    [`${VALID_ADDR2}:HIGH`],
    },
};

/**
 * Build the minimal DOM needed for the premium unlock flow.
 * Matches the structure created by createWalletRow() in index.html.
 */
function buildPremiumDom(addr) {
    document.body.innerHTML = `
        <div id="premium-payment-announce" aria-live="assertive" class="sr-only"></div>
        <table>
            <tbody>
                <tr>
                    <td colspan="8">
                        <div class="premium-unlock" data-pu-wallet="${addr}">
                            <div class="premium-unlock-locked">
                                <button class="btn-unlock-premium"
                                        data-wallet="${addr}"
                                        aria-label="Unlock premium forensic data for wallet ${addr}"
                                        aria-describedby="pu-tt-${addr}">
                                    \uD83D\uDD12 Unlock $0.11 via x402
                                </button>
                                <span class="pu-tooltip-wrap">
                                    <button class="pu-tooltip-trigger" type="button"
                                            aria-label="What you get with premium data">\u24d8</button>
                                    <span class="pu-tooltip-content" id="pu-tt-${addr}" role="tooltip">
                                        Unlock 6 premium data points: Add Liquidity Value,
                                        Remove Liquidity Value, Wallet Funding Source,
                                        Tokens Created (with Solscan links),
                                        Forensic Notes, and Cross-Project Risk Links.
                                    </span>
                                </span>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr class="premium-detail-row" data-pu-detail="${addr}">
                    <td colspan="8">
                        <div class="premium-card" data-pu-card="${addr}"></div>
                    </td>
                </tr>
            </tbody>
        </table>
    `;
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Locked premium section — initial UI state
// ════════════════════════════════════════════════════════════════════════════

describe('1. Locked premium section — initial UI state', () => {
    beforeEach(() => {
        buildPremiumDom(VALID_ADDR);
    });

    afterEach(() => {
        document.body.innerHTML = '';
    });

    test('renders .btn-unlock-premium with correct data-wallet attribute', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn).not.toBeNull();
        expect(btn.dataset.wallet).toBe(VALID_ADDR);
    });

    test('unlock button text includes "Unlock" and "$0.11"', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn.textContent).toContain('Unlock');
        expect(btn.textContent).toContain('0.11');
    });

    test('unlock button has aria-label describing the wallet address', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn.getAttribute('aria-label')).toContain(VALID_ADDR);
    });

    test('renders .premium-unlock container with data-pu-wallet attribute', () => {
        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container).not.toBeNull();
    });

    test('renders .premium-detail-row with data-pu-detail attribute (initially not visible)', () => {
        const detailRow = document.querySelector(`.premium-detail-row[data-pu-detail="${VALID_ADDR}"]`);
        expect(detailRow).not.toBeNull();
        expect(detailRow.classList.contains('visible')).toBe(false);
    });

    test('renders .premium-card with data-pu-card attribute (initially empty)', () => {
        const card = document.querySelector(`.premium-card[data-pu-card="${VALID_ADDR}"]`);
        expect(card).not.toBeNull();
        expect(card.innerHTML.trim()).toBe('');
    });

    test('tooltip content mentions "6 premium data points"', () => {
        const tooltip = document.querySelector('.pu-tooltip-content');
        expect(tooltip).not.toBeNull();
        expect(tooltip.textContent).toContain('6 premium data points');
    });

    test('tooltip trigger has accessible aria-label', () => {
        const trigger = document.querySelector('.pu-tooltip-trigger');
        expect(trigger).not.toBeNull();
        expect(trigger.getAttribute('aria-label')).toBeTruthy();
    });

    test('#premium-payment-announce aria-live region exists with "assertive"', () => {
        const announcer = document.getElementById('premium-payment-announce');
        expect(announcer).not.toBeNull();
        expect(announcer.getAttribute('aria-live')).toBe('assertive');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. Full x402 payment flow — probe 402 → requestPayment → retry → success
// ════════════════════════════════════════════════════════════════════════════

describe('2. Full x402 payment flow — probe 402 → payment → success', () => {
    const PAYMENT_TOKEN = 'x402-tok-abc123';

    beforeEach(() => {
        buildPremiumDom(VALID_ADDR);

        // Mock the x402 SDK — already available (fast path in loadX402Sdk)
        window.x402 = {
            requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN),
        };

        // Mock fetch:
        //   call 1 → probe  → 402 with requiredAmountUSD
        //   call 2 → retry  → 200 with premium data
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402,
                ok: false,
                json: jest.fn().mockResolvedValue({ requiredAmountUSD: 0.11 }),
            })
            .mockResolvedValueOnce({
                status: 200,
                ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });
    });

    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    test('transitions to loading state immediately on unlock', async () => {
        const promise = unlockPremiumData(VALID_ADDR);
        // Loading state is set synchronously before the first await
        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container.querySelector('.premium-unlock-loading')).not.toBeNull();
        await promise;
    });

    test('announces "Initiating x402 payment" at the start of the flow', async () => {
        const announcer = document.getElementById('premium-payment-announce');
        const promise = unlockPremiumData(VALID_ADDR);
        // Announcement is set synchronously before any await
        expect(announcer.textContent).toContain('Initiating x402 payment');
        await promise;
    });

    test('probes the correct API endpoint with POST', async () => {
        await unlockPremiumData(VALID_ADDR);
        const expectedEndpoint =
            `${API_BASE_URL}/wallets/${encodeURIComponent(VALID_ADDR)}/premium/access`;
        expect(global.fetch).toHaveBeenNthCalledWith(
            1,
            expectedEndpoint,
            { method: 'POST' }
        );
    });

    test('calls window.x402.requestPayment with correct payment args', async () => {
        await unlockPremiumData(VALID_ADDR);
        expect(window.x402.requestPayment).toHaveBeenCalledWith({
            amount:    0.11,
            currency:  'USD',
            recipient: 'suspected.dev',
            memo:      `Premium forensic data: ${VALID_ADDR}`,
        });
    });

    test('retries the endpoint with x402-payment header after payment', async () => {
        await unlockPremiumData(VALID_ADDR);
        const expectedEndpoint =
            `${API_BASE_URL}/wallets/${encodeURIComponent(VALID_ADDR)}/premium/access`;
        expect(global.fetch).toHaveBeenNthCalledWith(
            2,
            expectedEndpoint,
            { method: 'POST', headers: { 'x402-payment': PAYMENT_TOKEN } }
        );
    });

    test('transitions to success state after payment completes', async () => {
        await unlockPremiumData(VALID_ADDR);
        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
        expect(container.querySelector('.premium-unlock-loading')).toBeNull();
    });

    test('success state text confirms unlock', async () => {
        await unlockPremiumData(VALID_ADDR);
        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container.textContent).toContain('Unlocked');
    });

    test('makes the .premium-detail-row visible after success', async () => {
        await unlockPremiumData(VALID_ADDR);
        const detailRow = document.querySelector(`.premium-detail-row[data-pu-detail="${VALID_ADDR}"]`);
        expect(detailRow.classList.contains('visible')).toBe(true);
    });

    test('renders all six premium field labels', async () => {
        await unlockPremiumData(VALID_ADDR);
        const labels = Array.from(
            document.querySelectorAll('.premium-card-label')
        ).map(el => el.textContent.trim());
        expect(labels).toContain('Add Liquidity Value');
        expect(labels).toContain('Remove Liquidity Value');
        expect(labels).toContain('Wallet Funding');
        expect(labels).toContain('Tokens Created');
        expect(labels).toContain('Forensic Notes');
        expect(labels).toContain('Cross-Project Links');
    });

    test('Add Liquidity Value field displays the correct value', async () => {
        await unlockPremiumData(VALID_ADDR);
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Add Liquidity Value')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toBe('15.5 SOL');
    });

    test('Remove Liquidity Value field displays the correct value', async () => {
        await unlockPremiumData(VALID_ADDR);
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Remove Liquidity Value')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toBe('12.3 SOL');
    });

    test('Wallet Funding field displays the correct value', async () => {
        await unlockPremiumData(VALID_ADDR);
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Wallet Funding')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('CEX withdrawal');
    });

    test('Tokens Created field renders a Solscan link for a valid address', async () => {
        await unlockPremiumData(VALID_ADDR);
        const link = document.querySelector('a.premium-token-link');
        expect(link).not.toBeNull();
        expect(link.getAttribute('href')).toBe(`https://solscan.io/token/${VALID_ADDR2}`);
        expect(link.getAttribute('rel')).toContain('noopener');
        expect(link.getAttribute('rel')).toContain('noreferrer');
        expect(link.getAttribute('target')).toBe('_blank');
    });

    test('Forensic Notes field displays the correct value', async () => {
        await unlockPremiumData(VALID_ADDR);
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Forensic Notes')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('rug-pull pattern');
    });

    test('Cross-Project Links field renders address with HIGH risk badge', async () => {
        await unlockPremiumData(VALID_ADDR);
        const badge = document.querySelector('.risk-badge-high');
        expect(badge).not.toBeNull();
        expect(badge.textContent.trim()).toBe('HIGH');
    });

    test('premium card header includes the wallet address', async () => {
        await unlockPremiumData(VALID_ADDR);
        const header = document.querySelector('.premium-card-header');
        expect(header).not.toBeNull();
        expect(header.textContent).toContain(VALID_ADDR);
    });

    test('uses requiredAmountUSD from 402 response if provided', async () => {
        // Re-mock with a non-default amount
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402,
                ok: false,
                json: jest.fn().mockResolvedValue({ requiredAmountUSD: 0.25 }),
            })
            .mockResolvedValueOnce({
                status: 200,
                ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });
        await unlockPremiumData(VALID_ADDR);
        expect(window.x402.requestPayment).toHaveBeenCalledWith(
            expect.objectContaining({ amount: 0.25 })
        );
    });

    test('falls back to 0.11 when 402 response has no requiredAmountUSD', async () => {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402,
                ok: false,
                json: jest.fn().mockResolvedValue({}),   // no requiredAmountUSD
            })
            .mockResolvedValueOnce({
                status: 200,
                ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });
        await unlockPremiumData(VALID_ADDR);
        expect(window.x402.requestPayment).toHaveBeenCalledWith(
            expect.objectContaining({ amount: 0.11 })
        );
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. XSS protection — malicious strings in premium fields are HTML-escaped
// ════════════════════════════════════════════════════════════════════════════

describe('3. XSS protection — malicious strings in premium fields are escaped', () => {
    beforeEach(() => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = {
            requestPayment: jest.fn().mockResolvedValue('tok'),
        };
    });

    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    function mockFetchWith(premiumForensics) {
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue({ premiumForensics }),
            });
    }

    test('<script> tag in forensicNotes is escaped, not executed', async () => {
        mockFetchWith({ forensicNotes: '<script>alert(1)</script>' });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('script')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('<img onerror> in addLiquidityValue is escaped, not executed', async () => {
        mockFetchWith({ addLiquidityValue: '<img src=x onerror=alert(1)>' });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('img')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;img');
    });

    test('<svg onload> in walletFunding is escaped, not executed', async () => {
        mockFetchWith({ walletFunding: '"><svg onload=alert(1)>' });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('svg')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;svg');
    });

    test('<script> tag in removeLiquidityValue is escaped, not executed', async () => {
        mockFetchWith({ removeLiquidityValue: '<script>evil()</script>' });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('script')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('XSS payload in crossProjectLinks address part is escaped, not linked', async () => {
        mockFetchWith({ crossProjectLinks: ['<script>evil()</script>:HIGH'] });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('script')).toBeNull();
        expect(document.querySelector('a.premium-token-link')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('double-quote injection in forensicNotes does not create executable handlers', async () => {
        mockFetchWith({ forensicNotes: '" onmouseover="evil()' });
        await unlockPremiumData(VALID_ADDR);
        // The value must appear as visible text, not as attribute injection
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Forensic Notes')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('"');
        // No onmouseover handlers injected into the DOM
        const allElements = document.querySelectorAll('[onmouseover]');
        expect(allElements.length).toBe(0);
    });

    test('single-quote in walletFunding is rendered as safe text in HTML context', async () => {
        mockFetchWith({ walletFunding: "'; DROP TABLE wallets; --" });
        await unlockPremiumData(VALID_ADDR);
        // The single quote must appear as visible text
        const values = document.querySelectorAll('.premium-card-value');
        const field = Array.from(values).find(v =>
            v.previousElementSibling &&
            v.previousElementSibling.textContent.includes('Wallet Funding')
        );
        expect(field).not.toBeNull();
        expect(field.textContent).toContain("'");
        // No unexpected child elements injected
        expect(field.querySelector('script')).toBeNull();
    });

    test('& ampersand in forensicNotes is HTML-encoded', async () => {
        mockFetchWith({ forensicNotes: 'A&B Investments' });
        await unlockPremiumData(VALID_ADDR);
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&amp;');
        expect(document.querySelector('script')).toBeNull();
    });

    test('invalid token address in tokensCreated is rendered as escaped text, not a link', async () => {
        mockFetchWith({ tokensCreated: ['<script>evil()</script>'] });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('script')).toBeNull();
        expect(document.querySelector('a.premium-token-link')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('error message from a failed probe is HTML-escaped before display', async () => {
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: '<img onerror=x src=x>' }),
        });
        await unlockPremiumData(VALID_ADDR);
        expect(document.querySelector('img')).toBeNull();
        const errSpan = document.querySelector('.premium-unlock-error-msg');
        expect(errSpan).not.toBeNull();
        expect(errSpan.innerHTML).toContain('&lt;img');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. Already-authorized path — 200 on probe renders card directly
// ════════════════════════════════════════════════════════════════════════════

describe('4. Already-authorized path — 200 on probe skips payment modal', () => {
    beforeEach(() => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = {
            requestPayment: jest.fn(),
        };
        // Single fetch call — probe returns 200 directly
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
        });
    });

    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    test('only one fetch call is made (no retry)', async () => {
        await unlockPremiumData(VALID_ADDR);
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    test('window.x402.requestPayment is NOT called', async () => {
        await unlockPremiumData(VALID_ADDR);
        expect(window.x402.requestPayment).not.toHaveBeenCalled();
    });

    test('transitions to success state', async () => {
        await unlockPremiumData(VALID_ADDR);
        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
    });

    test('renders the premium card with all six fields', async () => {
        await unlockPremiumData(VALID_ADDR);
        const labels = Array.from(
            document.querySelectorAll('.premium-card-label')
        ).map(el => el.textContent.trim());
        expect(labels.length).toBe(6);
    });

    test('makes the detail row visible', async () => {
        await unlockPremiumData(VALID_ADDR);
        const detailRow = document.querySelector(`.premium-detail-row[data-pu-detail="${VALID_ADDR}"]`);
        expect(detailRow.classList.contains('visible')).toBe(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. Error states
// ════════════════════════════════════════════════════════════════════════════

describe('5. Error states', () => {
    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
        jest.restoreAllMocks();
    });

    test('shows SDK unavailable error when x402 is absent after script load', async () => {
        buildPremiumDom(VALID_ADDR);
        delete window.x402;

        // Mock script injection to fire the load event immediately
        // so loadX402Sdk resolves, but window.x402 remains undefined
        jest.spyOn(document.head, 'appendChild').mockImplementation(function(el) {
            if (el && el.tagName === 'SCRIPT') {
                Promise.resolve().then(function() {
                    el.dispatchEvent(new Event('load'));
                });
            }
            return el;
        });

        await unlockPremiumData(VALID_ADDR);

        const errMsg = document.querySelector('.premium-unlock-error-msg');
        expect(errMsg).not.toBeNull();
        expect(errMsg.textContent).toContain('x402 SDK unavailable');
    });

    test('shows error + retry button when probe returns a non-402/non-200 status', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: 'Internal server error' }),
        });

        await unlockPremiumData(VALID_ADDR);

        const errMsg = document.querySelector('.premium-unlock-error-msg');
        expect(errMsg).not.toBeNull();
        expect(errMsg.textContent).toContain('Internal server error');

        const retryBtn = document.querySelector('.btn-premium-retry');
        expect(retryBtn).not.toBeNull();
        expect(retryBtn.dataset.wallet).toBe(VALID_ADDR);
    });

    test('retry button data-wallet attribute is HTML-escaped (no injection)', async () => {
        // Wallet address passes base58 validation so no injection possible,
        // but verify the attribute is properly set regardless
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: 'err' }),
        });

        await unlockPremiumData(VALID_ADDR);

        const retryBtn = document.querySelector('.btn-premium-retry');
        expect(retryBtn).not.toBeNull();
        // The data-wallet attribute should exactly equal the address (no extra markup)
        expect(retryBtn.dataset.wallet).toBe(VALID_ADDR);
    });

    test('shows payment-failed error when retry request returns non-200', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue('tok') };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 403, ok: false,
                json: jest.fn().mockResolvedValue({ message: 'Payment token invalid' }),
            });

        await unlockPremiumData(VALID_ADDR);

        const errMsg = document.querySelector('.premium-unlock-error-msg');
        expect(errMsg).not.toBeNull();
        expect(errMsg.textContent).toContain('Payment failed');
        expect(errMsg.textContent).toContain('Payment token invalid');

        const retryBtn = document.querySelector('.btn-premium-retry');
        expect(retryBtn).not.toBeNull();
    });

    test('shows error when fetch throws a network error', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn().mockRejectedValue(new Error('Network failure'));

        await unlockPremiumData(VALID_ADDR);

        const errMsg = document.querySelector('.premium-unlock-error-msg');
        expect(errMsg).not.toBeNull();
        expect(errMsg.textContent).toContain('Network failure');
    });

    test('network error message is HTML-escaped before display', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn().mockRejectedValue(
            new Error('<script>alert("xss")</script>')
        );

        await unlockPremiumData(VALID_ADDR);

        expect(document.querySelector('script')).toBeNull();
        const errMsg = document.querySelector('.premium-unlock-error-msg');
        expect(errMsg.innerHTML).toContain('&lt;script&gt;');
    });

    test('shows error without retry button when SDK is unavailable', async () => {
        buildPremiumDom(VALID_ADDR);
        delete window.x402;

        jest.spyOn(document.head, 'appendChild').mockImplementation(function(el) {
            if (el && el.tagName === 'SCRIPT') {
                Promise.resolve().then(function() {
                    el.dispatchEvent(new Event('load'));
                });
            }
            return el;
        });

        await unlockPremiumData(VALID_ADDR);

        // SDK-unavailable path does not show a retry button
        expect(document.querySelector('.btn-premium-retry')).toBeNull();
        expect(document.querySelector('.premium-unlock-error-msg')).not.toBeNull();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 6. Event delegation — button clicks trigger the unlock flow
// ════════════════════════════════════════════════════════════════════════════

// Replicated verbatim from index.html (document.addEventListener block)
function handleDelegatedClick(e) {
    const unlockBtn = e.target.closest('.btn-unlock-premium');
    if (unlockBtn) {
        const addr = unlockBtn.dataset.wallet || '';
        if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) {
            unlockPremiumData(addr);
        }
        return;
    }
    const retryBtn = e.target.closest('.btn-premium-retry');
    if (retryBtn) {
        const addr = retryBtn.dataset.wallet || '';
        if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(addr)) {
            unlockPremiumData(addr);
        }
    }
}

describe('6. Event delegation — button clicks trigger the unlock flow', () => {
    beforeEach(() => {
        document.addEventListener('click', handleDelegatedClick);
    });

    afterEach(() => {
        document.removeEventListener('click', handleDelegatedClick);
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
        jest.restoreAllMocks();
    });

    test('clicking .btn-unlock-premium with a valid address triggers unlockPremiumData', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue('tok') };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });

        const btn = document.querySelector('.btn-unlock-premium');
        btn.click();

        // Drain all microtasks and macrotasks so the async flow completes
        await new Promise(resolve => setTimeout(resolve, 0));

        expect(global.fetch).toHaveBeenCalled();
        expect(global.fetch).toHaveBeenCalledWith(
            expect.stringContaining(VALID_ADDR),
            expect.objectContaining({ method: 'POST' })
        );
    });

    test('clicking .btn-unlock-premium injects the x402 SDK script when x402 is absent', async () => {
        buildPremiumDom(VALID_ADDR);
        delete window.x402;

        let injectedScript = null;
        jest.spyOn(document.head, 'appendChild').mockImplementation(function(el) {
            if (el && el.tagName === 'SCRIPT') {
                injectedScript = el;
                // Capture without firing load — we only need to verify injection
            }
            return el;
        });

        const btn = document.querySelector('.btn-unlock-premium');
        btn.click();

        // Script injection happens synchronously inside the loadX402Sdk Promise executor;
        // one microtask flush is more than enough to confirm it.
        await Promise.resolve();

        expect(injectedScript).not.toBeNull();
        expect(injectedScript.src).toContain('x402gateway.io');
    });

    test('clicking .btn-unlock-premium with invalid address is a no-op', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn();

        const btn = document.querySelector('.btn-unlock-premium');
        // Overwrite data-wallet with an invalid address
        btn.dataset.wallet = 'INVALID!@#$';
        btn.click();

        await new Promise(resolve => setTimeout(resolve, 0));

        // fetch must not have been called for an invalid address
        expect(global.fetch).not.toHaveBeenCalled();
    });

    test('clicking .btn-premium-retry re-triggers the unlock flow', async () => {
        buildPremiumDom(VALID_ADDR);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue('tok') };

        // First call: probe returns 500 so retry button appears
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: 'error' }),
        });

        await unlockPremiumData(VALID_ADDR);

        // Retry button should now be in the DOM
        const retryBtn = document.querySelector('.btn-premium-retry');
        expect(retryBtn).not.toBeNull();

        // Second flow: probe 402 → success
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });

        retryBtn.click();

        await new Promise(resolve => setTimeout(resolve, 0));

        const container = document.querySelector(`.premium-unlock[data-pu-wallet="${VALID_ADDR}"]`);
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
    });
});

/**
 * E2E scenario tests for the full premium unlock flow — index.html
 * File: frontend/tests/premium-unlock.e2e.spec.js
 *
 * SCENARIO: User visits /wallet/7xKjT9q4PeR3mNvWxYz8dL2aB5cFgH1iJkLmNoP
 *
 * End-to-end coverage using Jest + jsdom with fetch and x402 SDK fully mocked:
 *   Step 1. Locked premium section visible: button text, aria attributes, tooltip
 *   Step 2. Click unlock → loading state → x402 SDK called → payment modal appears
 *   Step 3. Successful payment → API retry includes x402-payment header → success state
 *   Step 4. Premium forensic card loads with all 6 fields properly escaped and formatted
 *   Step 5. tokensCreated: valid Solana addresses → Solscan links; invalid → plain text
 *   Step 6. XSS protection: forensicNotes with <script>alert(1)</script> renders as escaped text
 *
 * Run (from frontend/ directory):
 *   npm test
 *   npm test -- tests/premium-unlock.e2e.spec.js
 */

'use strict';

// ── CSS.escape polyfill — not available in Jest/jsdom ────────────────────────
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

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

const SOLANA_ADDR_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

const API_BASE_URL = 'https://suspected.dev/api';

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

// ── Shared scenario fixtures ──────────────────────────────────────────────────

/**
 * SCENARIO_WALLET represents the wallet address from the URL
 *   /wallet/7xKjT9q4PeR3mNvWxYz8dL2aB5cFgH1iJkLmNoP
 * 39-char Solana Base58 address (valid: 32–44 chars, no 0/O/I/l).
 */
const SCENARIO_WALLET = '7xKjT9q4PeR3mNvWxYz8dL2aB5cFgH1iJkLmNoP';

/** Valid 44-char Solana token address used in tokensCreated. */
const VALID_TOKEN_ADDR = 'ZeKaYDCPcCRFY9jHV4qHikWb3d6z4xB9SuKH1j6U2vxf';

/** Invalid token address — not a valid Solana Base58 address (too short). */
const INVALID_TOKEN_ADDR = 'bad-token-addr';

const PAYMENT_TOKEN = 'x402-tok-e2e-scenario-abc123';

/** Full premium forensics payload — all six fields populated. */
const FULL_PREMIUM_DATA = {
    premiumForensics: {
        addLiquidityValue:    '42 SOL',
        removeLiquidityValue: '38.5 SOL',
        walletFunding:        'Binance withdrawal — hot wallet',
        tokensCreated:        [VALID_TOKEN_ADDR],
        forensicNotes:        'Rug-pull pattern: liquidity removed 4 h after launch.',
        crossProjectLinks:    [`${VALID_TOKEN_ADDR}:HIGH`],
    },
};

/**
 * Build the minimal DOM fragment that simulates the wallet row rendered by
 * createWalletRow() in index.html for the given wallet address.
 *
 * Mirrors the exact HTML structure expected by unlockPremiumData() and
 * renderPremiumCard() — including the aria-live announcer region.
 */
function buildScenarioDom(addr) {
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
// Step 1: Locked premium section — initial page state
// User visits /wallet/7xKjT9q4PeR3mNvWxYz8dL2aB5cFgH1iJkLmNoP and sees
// the locked premium forensics section with unlock button and price.
// ════════════════════════════════════════════════════════════════════════════

describe('Step 1: Locked premium section — initial page state', () => {
    beforeEach(() => {
        buildScenarioDom(SCENARIO_WALLET);
    });

    afterEach(() => {
        document.body.innerHTML = '';
    });

    test('locked section is present for the scenario wallet address', () => {
        const container = document.querySelector(
            `.premium-unlock[data-pu-wallet="${SCENARIO_WALLET}"]`
        );
        expect(container).not.toBeNull();
    });

    test('unlock button is visible with the lock icon and price "$0.11"', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn).not.toBeNull();
        expect(btn.textContent).toContain('Unlock');
        expect(btn.textContent).toContain('0.11');
        // Lock emoji present
        expect(btn.textContent).toContain('\uD83D\uDD12');
    });

    test('unlock button data-wallet attribute equals the scenario wallet address', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn.dataset.wallet).toBe(SCENARIO_WALLET);
    });

    test('unlock button aria-label references the scenario wallet address', () => {
        const btn = document.querySelector('.btn-unlock-premium');
        expect(btn.getAttribute('aria-label')).toContain(SCENARIO_WALLET);
    });

    test('premium detail row is in the DOM but not yet visible', () => {
        const detailRow = document.querySelector(
            `.premium-detail-row[data-pu-detail="${SCENARIO_WALLET}"]`
        );
        expect(detailRow).not.toBeNull();
        expect(detailRow.classList.contains('visible')).toBe(false);
    });

    test('premium card container starts empty', () => {
        const card = document.querySelector(
            `.premium-card[data-pu-card="${SCENARIO_WALLET}"]`
        );
        expect(card).not.toBeNull();
        expect(card.innerHTML.trim()).toBe('');
    });

    test('tooltip mentions all 6 premium data points', () => {
        const tooltip = document.querySelector('.pu-tooltip-content');
        expect(tooltip).not.toBeNull();
        expect(tooltip.textContent).toContain('6 premium data points');
    });

    test('aria-live announcer region exists and is set to "assertive"', () => {
        const announcer = document.getElementById('premium-payment-announce');
        expect(announcer).not.toBeNull();
        expect(announcer.getAttribute('aria-live')).toBe('assertive');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Step 2 & 3: Full x402 payment flow
// Click unlock → payment modal appears (mocked SDK) → payment succeeds →
// API retry includes x402-payment header → success state shown.
// ════════════════════════════════════════════════════════════════════════════

describe('Steps 2–3: x402 payment modal and successful payment', () => {
    beforeEach(() => {
        buildScenarioDom(SCENARIO_WALLET);

        // Mock x402gateway.io SDK — already available (fast path in loadX402Sdk)
        window.x402 = {
            requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN),
        };

        // fetch call 1: probe → 402 with requiredAmountUSD
        // fetch call 2: retry → 200 with premium forensics data
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

    test('clicking unlock shows loading state immediately', async () => {
        const promise = unlockPremiumData(SCENARIO_WALLET);
        // Loading state is set synchronously before any await
        const container = document.querySelector(
            `.premium-unlock[data-pu-wallet="${SCENARIO_WALLET}"]`
        );
        expect(container.querySelector('.premium-unlock-loading')).not.toBeNull();
        await promise;
    });

    test('aria-live region announces payment initiation', async () => {
        const announcer = document.getElementById('premium-payment-announce');
        const promise = unlockPremiumData(SCENARIO_WALLET);
        expect(announcer.textContent).toContain('Initiating x402 payment');
        await promise;
    });

    test('Step 2: probe POSTs to the correct wallet endpoint', async () => {
        await unlockPremiumData(SCENARIO_WALLET);
        const expected = `${API_BASE_URL}/wallets/${encodeURIComponent(SCENARIO_WALLET)}/premium/access`;
        expect(global.fetch).toHaveBeenNthCalledWith(1, expected, { method: 'POST' });
    });

    test('Step 2: x402 payment modal is triggered with correct args (mocked SDK)', async () => {
        await unlockPremiumData(SCENARIO_WALLET);
        expect(window.x402.requestPayment).toHaveBeenCalledTimes(1);
        expect(window.x402.requestPayment).toHaveBeenCalledWith({
            amount:    0.11,
            currency:  'USD',
            recipient: 'suspected.dev',
            memo:      `Premium forensic data: ${SCENARIO_WALLET}`,
        });
    });

    test('Step 3: API retry includes x402-payment header with the payment token', async () => {
        await unlockPremiumData(SCENARIO_WALLET);
        const expected = `${API_BASE_URL}/wallets/${encodeURIComponent(SCENARIO_WALLET)}/premium/access`;
        expect(global.fetch).toHaveBeenNthCalledWith(
            2,
            expected,
            { method: 'POST', headers: { 'x402-payment': PAYMENT_TOKEN } }
        );
    });

    test('Step 3: success state is shown after payment completes (loading state gone)', async () => {
        await unlockPremiumData(SCENARIO_WALLET);
        const container = document.querySelector(
            `.premium-unlock[data-pu-wallet="${SCENARIO_WALLET}"]`
        );
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
        expect(container.querySelector('.premium-unlock-loading')).toBeNull();
        expect(container.textContent).toContain('Unlocked');
    });

    test('Step 3: premium detail row becomes visible after successful unlock', async () => {
        await unlockPremiumData(SCENARIO_WALLET);
        const detailRow = document.querySelector(
            `.premium-detail-row[data-pu-detail="${SCENARIO_WALLET}"]`
        );
        expect(detailRow.classList.contains('visible')).toBe(true);
    });

    test('x402 SDK load is attempted via cdn.x402gateway.io when SDK is absent', async () => {
        // Simulate SDK absent — force loadX402Sdk to inject a <script> tag
        delete window.x402;

        let injectedScript = null;
        jest.spyOn(document.head, 'appendChild').mockImplementation(function(el) {
            if (el && el.tagName === 'SCRIPT') {
                injectedScript = el;
                // Immediately set window.x402 and fire load so the flow can continue
                window.x402 = { requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN) };
                Promise.resolve().then(function() {
                    el.dispatchEvent(new Event('load'));
                });
            }
            return el;
        });

        await unlockPremiumData(SCENARIO_WALLET);

        expect(injectedScript).not.toBeNull();
        expect(injectedScript.src).toContain('x402gateway.io');
        // crossOrigin maps to the crossorigin attribute in HTML; referrerPolicy is a
        // DOM property (not a reflected attribute in jsdom), so check it as a property.
        expect(injectedScript.getAttribute('crossorigin')).toBe('anonymous');
        expect(injectedScript.referrerPolicy).toBe('no-referrer');
    });

    test('requiredAmountUSD from 402 response is passed to requestPayment', async () => {
        // Reset mock call history so this test's assertion is isolated
        window.x402.requestPayment.mockClear();

        // Re-mock with a non-default amount
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({ requiredAmountUSD: 0.25 }),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });

        await unlockPremiumData(SCENARIO_WALLET);

        expect(window.x402.requestPayment).toHaveBeenCalledTimes(1);
        expect(window.x402.requestPayment).toHaveBeenCalledWith(
            expect.objectContaining({ amount: 0.25 })
        );
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Step 4: Premium forensic card — all 6 fields rendered and correctly labelled
// ════════════════════════════════════════════════════════════════════════════

describe('Step 4: Premium forensic card — all 6 fields rendered', () => {
    beforeEach(async () => {
        buildScenarioDom(SCENARIO_WALLET);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN) };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({ requiredAmountUSD: 0.11 }),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });
        await unlockPremiumData(SCENARIO_WALLET);
    });

    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    test('premium card header includes the wallet address', () => {
        const header = document.querySelector('.premium-card-header');
        expect(header).not.toBeNull();
        expect(header.textContent).toContain(SCENARIO_WALLET);
    });

    test('exactly 6 premium field labels are rendered', () => {
        const labels = document.querySelectorAll('.premium-card-label');
        expect(labels.length).toBe(6);
    });

    test('all 6 expected field labels are present', () => {
        const labelTexts = Array.from(
            document.querySelectorAll('.premium-card-label')
        ).map(el => el.textContent.trim());
        expect(labelTexts).toContain('Add Liquidity Value');
        expect(labelTexts).toContain('Remove Liquidity Value');
        expect(labelTexts).toContain('Wallet Funding');
        expect(labelTexts).toContain('Tokens Created');
        expect(labelTexts).toContain('Forensic Notes');
        expect(labelTexts).toContain('Cross-Project Links');
    });

    test('"Add Liquidity Value" field shows the correct value', () => {
        const field = Array.from(document.querySelectorAll('.premium-card-value'))
            .find(v => v.previousElementSibling &&
                v.previousElementSibling.textContent.includes('Add Liquidity Value'));
        expect(field).not.toBeNull();
        expect(field.textContent).toBe('42 SOL');
    });

    test('"Remove Liquidity Value" field shows the correct value', () => {
        const field = Array.from(document.querySelectorAll('.premium-card-value'))
            .find(v => v.previousElementSibling &&
                v.previousElementSibling.textContent.includes('Remove Liquidity Value'));
        expect(field).not.toBeNull();
        expect(field.textContent).toBe('38.5 SOL');
    });

    test('"Wallet Funding" field shows the correct value', () => {
        const field = Array.from(document.querySelectorAll('.premium-card-value'))
            .find(v => v.previousElementSibling &&
                v.previousElementSibling.textContent.includes('Wallet Funding'));
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('Binance withdrawal');
    });

    test('"Forensic Notes" field shows the correct value', () => {
        const field = Array.from(document.querySelectorAll('.premium-card-value'))
            .find(v => v.previousElementSibling &&
                v.previousElementSibling.textContent.includes('Forensic Notes'));
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('Rug-pull pattern');
    });

    test('"Cross-Project Links" field contains a HIGH risk badge', () => {
        const badge = document.querySelector('.risk-badge-high');
        expect(badge).not.toBeNull();
        expect(badge.textContent.trim()).toBe('HIGH');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Step 5: tokensCreated — valid Solana addresses link to Solscan;
//         invalid addresses render as plain escaped text.
// ════════════════════════════════════════════════════════════════════════════

describe('Step 5: tokensCreated — Solscan links vs plain text', () => {
    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    function setupWithTokens(tokensCreated) {
        buildScenarioDom(SCENARIO_WALLET);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN) };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue({
                    premiumForensics: {
                        addLiquidityValue:    '42 SOL',
                        removeLiquidityValue: '38.5 SOL',
                        walletFunding:        'Binance withdrawal',
                        forensicNotes:        'Test notes.',
                        // Explicitly empty crossProjectLinks so no cross-project
                        // anchor elements appear and interfere with the tokensCreated assertions.
                        crossProjectLinks:    [],
                        tokensCreated,
                    },
                }),
            });
        return unlockPremiumData(SCENARIO_WALLET);
    }

    test('valid Solana address in tokensCreated renders as a Solscan link', async () => {
        await setupWithTokens([VALID_TOKEN_ADDR]);
        const link = document.querySelector('a.premium-token-link');
        expect(link).not.toBeNull();
        expect(link.getAttribute('href')).toBe(`https://solscan.io/token/${VALID_TOKEN_ADDR}`);
        expect(link.getAttribute('target')).toBe('_blank');
        expect(link.getAttribute('rel')).toContain('noopener');
        expect(link.getAttribute('rel')).toContain('noreferrer');
        expect(link.textContent).toBe(VALID_TOKEN_ADDR);
    });

    test('invalid token address renders as plain escaped text — no link created', async () => {
        await setupWithTokens([INVALID_TOKEN_ADDR]);
        const link = document.querySelector('a.premium-token-link');
        expect(link).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.textContent).toContain(INVALID_TOKEN_ADDR);
    });

    test('mix of valid and invalid addresses: valid gets link, invalid gets plain text', async () => {
        await setupWithTokens([VALID_TOKEN_ADDR, INVALID_TOKEN_ADDR]);
        const links = document.querySelectorAll('a.premium-token-link');
        // Exactly one valid address → exactly one link
        expect(links.length).toBe(1);
        const hrefs = Array.from(links).map(a => a.getAttribute('href'));
        expect(hrefs.some(h => h.includes(VALID_TOKEN_ADDR))).toBe(true);
        expect(hrefs.every(h => !h.includes(INVALID_TOKEN_ADDR))).toBe(true);
        // Invalid address text is present somewhere in the card
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.textContent).toContain(INVALID_TOKEN_ADDR);
    });

    test('empty tokensCreated array renders an em-dash placeholder', async () => {
        await setupWithTokens([]);
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('\u2014');
        expect(document.querySelector('a.premium-token-link')).toBeNull();
    });

    test('Solscan token URL uses the exact address — no URL injection possible', async () => {
        // Address with URL-special chars must not pass the Base58 regex
        await setupWithTokens(['https://evil.io/steal?token=abc']);
        const link = document.querySelector('a.premium-token-link');
        expect(link).toBeNull();
    });
});

// ════════════════════════════════════════════════════════════════════════════
// Step 6: XSS protection — malicious strings in premium fields are HTML-escaped
// ════════════════════════════════════════════════════════════════════════════

describe('Step 6: XSS protection — malicious premium field values are escaped', () => {
    afterEach(() => {
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
    });

    function setupWithForensics(premiumForensics) {
        buildScenarioDom(SCENARIO_WALLET);
        window.x402 = { requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN) };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({}),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue({ premiumForensics }),
            });
        return unlockPremiumData(SCENARIO_WALLET);
    }

    test('<script>alert(1)</script> in forensicNotes renders as escaped text, not executed', async () => {
        await setupWithForensics({ forensicNotes: '<script>alert(1)</script>' });
        // No <script> element injected into the DOM
        expect(document.querySelector('script')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        // Raw tag must not appear — entities must be used instead
        expect(card.innerHTML).toContain('&lt;script&gt;');
        expect(card.innerHTML).not.toContain('<script>');
    });

    test('<img onerror=alert(1)> in addLiquidityValue is escaped, not executed', async () => {
        await setupWithForensics({ addLiquidityValue: '<img src=x onerror=alert(1)>' });
        expect(document.querySelector('img')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;img');
    });

    test('<svg onload=alert(1)> in walletFunding is escaped, not executed', async () => {
        await setupWithForensics({ walletFunding: '"><svg onload=alert(1)>' });
        expect(document.querySelector('svg')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;svg');
    });

    test('<script> in removeLiquidityValue is escaped, not executed', async () => {
        await setupWithForensics({ removeLiquidityValue: '<script>evil()</script>' });
        expect(document.querySelector('script')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('XSS payload in tokensCreated is escaped and not turned into a link', async () => {
        await setupWithForensics({ tokensCreated: ['<script>evil()</script>'] });
        expect(document.querySelector('script')).toBeNull();
        expect(document.querySelector('a.premium-token-link')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('XSS payload in crossProjectLinks address part is escaped and not linked', async () => {
        await setupWithForensics({ crossProjectLinks: ['<script>evil()</script>:HIGH'] });
        expect(document.querySelector('script')).toBeNull();
        expect(document.querySelector('a.premium-token-link')).toBeNull();
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&lt;script&gt;');
    });

    test('double-quote injection in forensicNotes does not create event handler attributes', async () => {
        await setupWithForensics({ forensicNotes: '" onmouseover="evil()' });
        const allWithHandler = document.querySelectorAll('[onmouseover]');
        expect(allWithHandler.length).toBe(0);
        // The literal quote must appear as visible text
        const field = Array.from(document.querySelectorAll('.premium-card-value'))
            .find(v => v.previousElementSibling &&
                v.previousElementSibling.textContent.includes('Forensic Notes'));
        expect(field).not.toBeNull();
        expect(field.textContent).toContain('"');
    });

    test('& ampersand in forensicNotes is HTML-encoded as &amp;', async () => {
        await setupWithForensics({ forensicNotes: 'Fund A&B Investments' });
        const card = document.querySelector('.premium-card[data-pu-card]');
        expect(card.innerHTML).toContain('&amp;');
    });

    test('error message from a failed probe is HTML-escaped before display', async () => {
        buildScenarioDom(SCENARIO_WALLET);
        window.x402 = { requestPayment: jest.fn() };
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: '<img onerror=x src=x>' }),
        });
        await unlockPremiumData(SCENARIO_WALLET);
        expect(document.querySelector('img')).toBeNull();
        const errSpan = document.querySelector('.premium-unlock-error-msg');
        expect(errSpan).not.toBeNull();
        expect(errSpan.innerHTML).toContain('&lt;img');
    });
});

// ════════════════════════════════════════════════════════════════════════════
// End-to-end scenario: full user journey in one continuous flow
// ════════════════════════════════════════════════════════════════════════════

describe('E2E scenario: complete user journey from locked to premium card', () => {
    // Event delegation handler — mirrors the one in index.html
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

    beforeEach(() => {
        buildScenarioDom(SCENARIO_WALLET);
        document.addEventListener('click', handleDelegatedClick);

        window.x402 = {
            requestPayment: jest.fn().mockResolvedValue(PAYMENT_TOKEN),
        };
        global.fetch = jest.fn()
            .mockResolvedValueOnce({
                status: 402, ok: false,
                json: jest.fn().mockResolvedValue({ requiredAmountUSD: 0.11 }),
            })
            .mockResolvedValueOnce({
                status: 200, ok: true,
                json: jest.fn().mockResolvedValue(FULL_PREMIUM_DATA),
            });
    });

    afterEach(() => {
        document.removeEventListener('click', handleDelegatedClick);
        document.body.innerHTML = '';
        delete window.x402;
        delete global.fetch;
        jest.restoreAllMocks();
    });

    test('full journey: click unlock → payment → card with all 6 fields via event delegation', async () => {
        // Step 1: premium section is locked
        expect(document.querySelector('.btn-unlock-premium')).not.toBeNull();
        expect(document.querySelector(
            `.premium-detail-row[data-pu-detail="${SCENARIO_WALLET}"]`
        ).classList.contains('visible')).toBe(false);

        // Step 2: user clicks the unlock button
        document.querySelector('.btn-unlock-premium').click();

        // Allow all microtasks and macrotasks to settle
        await new Promise(resolve => setTimeout(resolve, 0));

        // Step 3: probe was sent and x402 SDK was called
        expect(global.fetch).toHaveBeenCalledTimes(2);
        expect(window.x402.requestPayment).toHaveBeenCalledTimes(1);

        // x402-payment header was included in the retry
        const retryCall = global.fetch.mock.calls[1];
        expect(retryCall[1].headers['x402-payment']).toBe(PAYMENT_TOKEN);

        // Step 4: success state and detail row visible
        const container = document.querySelector(
            `.premium-unlock[data-pu-wallet="${SCENARIO_WALLET}"]`
        );
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
        expect(document.querySelector(
            `.premium-detail-row[data-pu-detail="${SCENARIO_WALLET}"]`
        ).classList.contains('visible')).toBe(true);

        // Step 4: all 6 field labels rendered
        const labels = Array.from(document.querySelectorAll('.premium-card-label'))
            .map(el => el.textContent.trim());
        expect(labels.length).toBe(6);
        ['Add Liquidity Value', 'Remove Liquidity Value', 'Wallet Funding',
            'Tokens Created', 'Forensic Notes', 'Cross-Project Links']
            .forEach(label => expect(labels).toContain(label));

        // Step 5: valid token address is a Solscan link
        const tokenLink = document.querySelector('a.premium-token-link');
        expect(tokenLink).not.toBeNull();
        expect(tokenLink.getAttribute('href')).toBe(`https://solscan.io/token/${VALID_TOKEN_ADDR}`);
    });

    test('retry button after error re-triggers the full payment flow', async () => {
        // Override fetch: first call returns 500 so retry button appears
        global.fetch = jest.fn().mockResolvedValueOnce({
            status: 500, ok: false,
            json: jest.fn().mockResolvedValue({ message: 'Server error' }),
        });

        await unlockPremiumData(SCENARIO_WALLET);

        const retryBtn = document.querySelector('.btn-premium-retry');
        expect(retryBtn).not.toBeNull();

        // Second flow: probe 402 → payment → success
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

        // Verify the full payment flow was executed on retry
        expect(window.x402.requestPayment).toHaveBeenCalledTimes(1);
        const container = document.querySelector(
            `.premium-unlock[data-pu-wallet="${SCENARIO_WALLET}"]`
        );
        expect(container.querySelector('.premium-unlock-success')).not.toBeNull();
    });
});

#!/usr/bin/env node
/**
 * scripts/check-frontend-security.js
 *
 * Pre-deploy security check for frontend/index.html.
 * Run from the repository root:
 *
 *   node scripts/check-frontend-security.js
 *
 * Exits 0 when all checks pass, 1 when any check fails.
 *
 * ─── Checks ──────────────────────────────────────────────────────────────────
 *
 * 1. innerHTML assignments without escapeHtml() wrapper (regex heuristic).
 *    Flags every .innerHTML = <expr> where <expr> is not a static string,
 *    an empty-string clear, or an expression that calls a known-safe wrapper
 *    (escapeHtml / safeInnerHtml / createWalletRow).
 *
 * 2. External <script src> and <link href> tags missing Subresource Integrity.
 *    Every resource loaded from an external origin (https://...) must carry
 *    both integrity="sha…" and crossorigin attributes.
 *
 * ─── Suppressing false positives ─────────────────────────────────────────────
 *
 * Append  // sc-ok  to the end of a line to suppress it from both checks.
 * Always add a short explanation of why the usage is safe:
 *
 *   tmpl.innerHTML = content; // sc-ok — inert <template>; scripts cannot execute
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Configuration ─────────────────────────────────────────────────────────────

const HTML_PATH = path.resolve(__dirname, '../frontend/index.html');

// Functions whose return values are considered safe for innerHTML.
// createWalletRow() wraps every API-sourced field in escapeHtml() internally.
// \b word-boundaries prevent substring matches like fakeEscapeHtml( from bypassing the check.
const SAFE_WRAPPERS = /\bescapeHtml\s*\(|\bsafeInnerHtml\s*\(|\bcreateWalletRow\s*\(/;

// ── ANSI helpers ──────────────────────────────────────────────────────────────

/* eslint-disable no-control-regex */
const C = {
    reset:  '\x1b[0m',
    bold:   '\x1b[1m',
    red:    '\x1b[31m',
    green:  '\x1b[32m',
    yellow: '\x1b[33m',
    cyan:   '\x1b[36m',
};
/* eslint-enable no-control-regex */

const sym = {
    pass: `${C.green}✔${C.reset}`,
    fail: `${C.red}✘${C.reset}`,
};

function heading(msg)   { console.log(`\n${C.bold}${msg}${C.reset}`); }
function logPass(msg)   { console.log(`  ${sym.pass}  ${msg}`); }
function logFail(msg)   { console.error(`  ${sym.fail}  ${msg}`); }
function logDetail(msg) { console.log(`     ${C.cyan}↳${C.reset}  ${msg}`); }

// ── Read HTML source ──────────────────────────────────────────────────────────

if (!fs.existsSync(HTML_PATH)) {
    console.error(`${C.red}ERROR${C.reset}: Cannot find ${HTML_PATH}`);
    process.exit(2);
}

const source = fs.readFileSync(HTML_PATH, 'utf-8');
const lines  = source.split('\n');

let totalFailures = 0;

// ════════════════════════════════════════════════════════════════════════════
// Check 1 — innerHTML assignments without escapeHtml() wrapper
// ════════════════════════════════════════════════════════════════════════════

heading('Check 1 — innerHTML assignments without escapeHtml() wrapper');

/**
 * Starting at lineIdx, collect lines that belong to the template literal whose
 * opening backtick starts at or after the first backtick on that line.
 * Returns { block: string, endLine: number }.
 *
 * The scan tracks `${}` nesting depth so it doesn't stop at a backtick that
 * is inside an interpolated expression.
 */
function collectTemplateLiteral(lineIdx) {
    const startCol = lines[lineIdx].indexOf('`');
    if (startCol === -1) return { block: '', endLine: lineIdx };

    let block  = '';
    let depth  = 0; // depth of ${} nesting (0 = still inside the template)

    for (let i = lineIdx; i < lines.length; i++) {
        const seg = (i === lineIdx) ? lines[i].slice(startCol) : lines[i];
        block += (block ? '\n' : '') + seg;

        // Walk character-by-character from just after the opening backtick
        const from = (i === lineIdx) ? 1 : 0;
        for (let k = from; k < seg.length; k++) {
            const ch = seg[k];
            if (ch === '\\') { k++; continue; } // skip escaped character

            if (depth === 0 && ch === '`') {
                // Matched the closing backtick of the outer template literal
                return { block, endLine: i };
            }
            if (ch === '$' && seg[k + 1] === '{') { depth++; k++; }
            else if (ch === '}' && depth > 0)     { depth--;      }
        }
    }

    // Unterminated template — return whatever was collected
    return { block, endLine: lines.length - 1 };
}

/**
 * Extract every top-level ${…} expression string from a template literal block.
 * Handles nested braces (e.g. object literals, arrow functions).
 */
function extractInterpolations(block) {
    const results = [];
    let depth     = 0;
    let exprStart = -1;

    for (let i = 0; i < block.length; i++) {
        const ch = block[i];
        if (ch === '\\') { i++; continue; } // skip escaped character

        if (ch === '$' && block[i + 1] === '{' && exprStart === -1) {
            exprStart = i + 2;
            depth     = 1;
            i++;
            continue;
        }

        if (exprStart >= 0) {
            if (ch === '{') depth++;
            else if (ch === '}') {
                depth--;
                if (depth === 0) {
                    results.push(block.slice(exprStart, i).trim());
                    exprStart = -1;
                }
            }
        }
    }

    return results;
}

const inlineIssues = [];

let i = 0;
while (i < lines.length) {
    const line    = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip lines suppressed by the // sc-ok annotation
    if (trimmed.includes('// sc-ok')) { i++; continue; }

    // Skip comment-only lines (JSDoc / single-line / block-comment continuation)
    if (trimmed.startsWith('//') ||
        trimmed.startsWith('*')  ||
        trimmed.startsWith('/*')) {
        i++;
        continue;
    }

    // Detect .innerHTML = <assignment> (not == comparison, not reading into a var)
    if (!/\.innerHTML\s*=[^=]/.test(line)) { i++; continue; }

    // Confirm the assignment operator comes AFTER .innerHTML
    // (eliminates "const x = el.innerHTML;" reads)
    const writeMatch = line.match(/\w[\w.]*\.innerHTML\s*=[^=]\s*(.*)/);
    if (!writeMatch) { i++; continue; }

    const rhs = writeMatch[1].trim();

    // ── Safe: empty-string clear (.innerHTML = '' / "" / ``) ─────────────────
    // Use a backreference (\1) to ensure the opening and closing quotes match.
    if (/^(['"`])\1\s*[;,]?\s*$/.test(rhs)) { i++; continue; }

    // ── Safe: static string literal (no template interpolation) ──────────────
    if ((rhs.startsWith("'") || rhs.startsWith('"')) && !rhs.includes('${')) {
        i++;
        continue;
    }

    // ── Template literal (may span multiple lines) ────────────────────────────
    if (rhs.startsWith('`')) {
        const { block, endLine } = collectTemplateLiteral(i);
        const expressions        = extractInterpolations(block);
        const unsafeExprs        = expressions.filter(expr => !SAFE_WRAPPERS.test(expr));

        if (unsafeExprs.length > 0) {
            inlineIssues.push({ lineNum, trimmed, unsafeExprs });
        }

        i = endLine + 1;
        continue;
    }

    // ── Variable / expression assignment ─────────────────────────────────────
    if (!SAFE_WRAPPERS.test(rhs) && !SAFE_WRAPPERS.test(line)) {
        inlineIssues.push({ lineNum, trimmed, unsafeExprs: [rhs.replace(/;$/, '')] });
    }

    i++;
}

if (inlineIssues.length === 0) {
    logPass('No unsafe innerHTML assignments detected.');
} else {
    totalFailures += inlineIssues.length;
    inlineIssues.forEach(({ lineNum, trimmed, unsafeExprs }) => {
        logFail(`Line ${lineNum}: ${trimmed}`);
        unsafeExprs.forEach(e => logDetail(`Unescaped expression: \${${e}}`));
    });
}

// ════════════════════════════════════════════════════════════════════════════
// Check 2 — External resources missing Subresource Integrity (SRI)
// ════════════════════════════════════════════════════════════════════════════

heading('Check 2 — External <script>/<link> tags missing integrity + crossorigin');

const sriIssues = [];

/**
 * Examine a single tag string and record any missing SRI attributes.
 */
function checkSri(tagStr, lineNum) {
    const hasIntegrity   = /\bintegrity\s*=/.test(tagStr);
    const hasCrossorigin = /\bcrossorigin\b/.test(tagStr);

    if (!hasIntegrity || !hasCrossorigin) {
        const missing = [];
        if (!hasIntegrity)   missing.push('integrity');
        if (!hasCrossorigin) missing.push('crossorigin');
        sriIssues.push({ lineNum, tagStr, missing });
    }
}

lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Respect the sc-ok suppression annotation
    if (trimmed.includes('// sc-ok')) return;

    // <script src="https://…"> tags (HTTPS only — HTTP cannot be trusted for SRI)
    const scriptRe = /<script\b[^>]*\bsrc\s*=\s*['"]https:\/\/[^'"]+['"][^>]*>/gi;
    let m;
    while ((m = scriptRe.exec(line)) !== null) {
        checkSri(m[0], lineNum);
    }

    // <link href="https://…"> tags (stylesheets, preloads, module preloads, etc.)
    const linkRe = /<link\b[^>]*\bhref\s*=\s*['"]https:\/\/[^'"]+['"][^>]*>/gi;
    while ((m = linkRe.exec(line)) !== null) {
        checkSri(m[0], lineNum);
    }
});

if (sriIssues.length === 0) {
    logPass('All external resources have integrity and crossorigin attributes.');
} else {
    totalFailures += sriIssues.length;
    sriIssues.forEach(({ lineNum, tagStr, missing }) => {
        const display = tagStr.length > 120 ? tagStr.slice(0, 120) + '…' : tagStr;
        logFail(`Line ${lineNum}: missing ${missing.join(', ')}`);
        logDetail(display);
    });
}

// ════════════════════════════════════════════════════════════════════════════
// Summary
// ════════════════════════════════════════════════════════════════════════════

heading('Summary');

if (totalFailures === 0) {
    logPass('All checks passed. OK to deploy.');
    process.exit(0);
} else {
    logFail(`${totalFailures} issue${totalFailures > 1 ? 's' : ''} found. Fix before deploying.`);
    process.exit(1);
}

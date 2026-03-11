/**
 * Theme Toggle Tests — index.html
 *
 * Tests the theme toggle functionality in index.html using Jest + jsdom:
 *   1. initThemeToggle() — verifies the function is correctly defined and wires the button
 *   2. Click handler     — verifies body class, localStorage, and icon classes toggle correctly
 *   3. Persistence       — verifies the initial state is restored from localStorage
 *   4. Both buttons      — verifies desktop (themeToggle) and mobile (themeToggleMobile) work
 *   5. Aria labels       — verifies aria-label is updated on each toggle
 *
 * Root cause fixed: a `</script>` string inside a JSDoc comment at line 1595 of index.html
 * caused the browser's HTML parser to prematurely close the <script> block.  As a result
 * every function defined after that point — including initThemeToggle and the
 * DOMContentLoaded handler that calls it — was never executed.  Fix: changed the inline
 * example to use `<\/script>` so the parser does not match it as a closing tag.
 *
 * Run (from frontend/ directory):
 *   npm test
 *   npm test -- tests/theme-toggle.test.js
 */

'use strict';

// ── initThemeToggle replicated verbatim from index.html ───────────────────────
// (mirrors initThemeToggle at index.html lines 1678-1724)

function initThemeToggle(buttonId) {
    const themeToggle = document.getElementById(buttonId);
    if (!themeToggle) return;

    const themeIcon = themeToggle.querySelector('i');
    const currentTheme = localStorage.getItem('theme') || 'dark';

    function updateAriaLabel(isLightMode) {
        themeToggle.setAttribute('aria-label', isLightMode ? 'Switch to dark mode' : 'Switch to light mode');
    }

    if (currentTheme === 'light') {
        document.body.classList.add('light-mode');
        if (themeIcon) {
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
        }
        updateAriaLabel(true);
    } else {
        updateAriaLabel(false);
    }

    themeToggle.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();

        document.body.classList.toggle('light-mode');

        const allIcons = document.querySelectorAll('.theme-toggle i');

        if (document.body.classList.contains('light-mode')) {
            allIcons.forEach(icon => {
                icon.classList.remove('fa-moon');
                icon.classList.add('fa-sun');
            });
            localStorage.setItem('theme', 'light');
            updateAriaLabel(true);
        } else {
            allIcons.forEach(icon => {
                icon.classList.remove('fa-sun');
                icon.classList.add('fa-moon');
            });
            localStorage.setItem('theme', 'dark');
            updateAriaLabel(false);
        }
    });
}

// ── Shared DOM fixture ────────────────────────────────────────────────────────

function setupDOM() {
    document.body.innerHTML = `
        <button type="button" class="theme-toggle" id="themeToggle" aria-label="Switch to light mode">
            <i class="fa-solid fa-moon"></i>
        </button>
        <button type="button" class="theme-toggle" id="themeToggleMobile" aria-label="Switch to light mode">
            <i class="fa-solid fa-moon"></i>
        </button>
    `;
    document.body.classList.remove('light-mode');
}

// ════════════════════════════════════════════════════════════════════════════
// 1. initThemeToggle() — function wiring
// ════════════════════════════════════════════════════════════════════════════

describe('1. initThemeToggle() — function wiring', () => {
    beforeEach(() => {
        setupDOM();
        localStorage.clear();
    });

    test('returns early when button ID does not exist', () => {
        expect(() => initThemeToggle('nonExistentButton')).not.toThrow();
    });

    test('attaches a click listener to the desktop toggle button', () => {
        initThemeToggle('themeToggle');
        const btn = document.getElementById('themeToggle');
        expect(btn).not.toBeNull();
        // Verify the listener is attached by clicking and checking side-effects
        btn.click();
        expect(document.body.classList.contains('light-mode')).toBe(true);
    });

    test('attaches a click listener to the mobile toggle button', () => {
        initThemeToggle('themeToggleMobile');
        const btn = document.getElementById('themeToggleMobile');
        expect(btn).not.toBeNull();
        btn.click();
        expect(document.body.classList.contains('light-mode')).toBe(true);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. Click handler — body class and localStorage
// ════════════════════════════════════════════════════════════════════════════

describe('2. Click handler — body class and localStorage', () => {
    beforeEach(() => {
        setupDOM();
        localStorage.clear();
        initThemeToggle('themeToggle');
        initThemeToggle('themeToggleMobile');
    });

    test('first click adds light-mode class to body', () => {
        document.getElementById('themeToggle').click();
        expect(document.body.classList.contains('light-mode')).toBe(true);
    });

    test('second click removes light-mode class from body', () => {
        const btn = document.getElementById('themeToggle');
        btn.click();
        btn.click();
        expect(document.body.classList.contains('light-mode')).toBe(false);
    });

    test('first click sets localStorage theme to "light"', () => {
        document.getElementById('themeToggle').click();
        expect(localStorage.getItem('theme')).toBe('light');
    });

    test('second click sets localStorage theme to "dark"', () => {
        const btn = document.getElementById('themeToggle');
        btn.click();
        btn.click();
        expect(localStorage.getItem('theme')).toBe('dark');
    });

    test('mobile toggle click adds light-mode class to body', () => {
        document.getElementById('themeToggleMobile').click();
        expect(document.body.classList.contains('light-mode')).toBe(true);
    });

    test('desktop and mobile toggles share the same body class state', () => {
        document.getElementById('themeToggle').click();     // light
        expect(document.body.classList.contains('light-mode')).toBe(true);
        document.getElementById('themeToggleMobile').click(); // dark
        expect(document.body.classList.contains('light-mode')).toBe(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. Icon class switching
// ════════════════════════════════════════════════════════════════════════════

describe('3. Icon class switching', () => {
    beforeEach(() => {
        setupDOM();
        localStorage.clear();
        initThemeToggle('themeToggle');
        initThemeToggle('themeToggleMobile');
    });

    test('clicking to light mode changes icon from fa-moon to fa-sun on all toggles', () => {
        document.getElementById('themeToggle').click();
        const icons = document.querySelectorAll('.theme-toggle i');
        icons.forEach(icon => {
            expect(icon.classList.contains('fa-sun')).toBe(true);
            expect(icon.classList.contains('fa-moon')).toBe(false);
        });
    });

    test('clicking back to dark mode changes icon from fa-sun to fa-moon on all toggles', () => {
        const btn = document.getElementById('themeToggle');
        btn.click(); // to light
        btn.click(); // back to dark
        const icons = document.querySelectorAll('.theme-toggle i');
        icons.forEach(icon => {
            expect(icon.classList.contains('fa-moon')).toBe(true);
            expect(icon.classList.contains('fa-sun')).toBe(false);
        });
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. localStorage persistence — initial state restored on init
// ════════════════════════════════════════════════════════════════════════════

describe('4. localStorage persistence', () => {
    beforeEach(() => {
        setupDOM();
    });

    test('when localStorage is empty, body starts without light-mode', () => {
        localStorage.clear();
        initThemeToggle('themeToggle');
        expect(document.body.classList.contains('light-mode')).toBe(false);
    });

    test('when localStorage has "light", initThemeToggle adds light-mode to body', () => {
        localStorage.setItem('theme', 'light');
        initThemeToggle('themeToggle');
        expect(document.body.classList.contains('light-mode')).toBe(true);
    });

    test('when localStorage has "dark", body stays without light-mode', () => {
        localStorage.setItem('theme', 'dark');
        initThemeToggle('themeToggle');
        expect(document.body.classList.contains('light-mode')).toBe(false);
    });

    test('when localStorage has "light", the icon is initialized to fa-sun', () => {
        localStorage.setItem('theme', 'light');
        initThemeToggle('themeToggle');
        const icon = document.querySelector('#themeToggle i');
        expect(icon.classList.contains('fa-sun')).toBe(true);
        expect(icon.classList.contains('fa-moon')).toBe(false);
    });
});

// ════════════════════════════════════════════════════════════════════════════
// 5. Aria-label updates
// ════════════════════════════════════════════════════════════════════════════

describe('5. Aria-label updates', () => {
    beforeEach(() => {
        setupDOM();
        localStorage.clear();
        initThemeToggle('themeToggle');
        initThemeToggle('themeToggleMobile');
    });

    test('desktop toggle aria-label starts as "Switch to light mode" (dark mode default)', () => {
        expect(document.getElementById('themeToggle').getAttribute('aria-label'))
            .toBe('Switch to light mode');
    });

    test('clicking desktop toggle updates its aria-label to "Switch to dark mode"', () => {
        document.getElementById('themeToggle').click();
        expect(document.getElementById('themeToggle').getAttribute('aria-label'))
            .toBe('Switch to dark mode');
    });

    test('clicking desktop toggle twice restores aria-label to "Switch to light mode"', () => {
        const btn = document.getElementById('themeToggle');
        btn.click();
        btn.click();
        expect(btn.getAttribute('aria-label')).toBe('Switch to light mode');
    });
});

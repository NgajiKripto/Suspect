'use strict';

describe('Theme Toggle Sanity', () => {
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

  beforeEach(() => {
    document.body.innerHTML = `
      <button type="button" class="theme-toggle" id="themeToggle" aria-label="Switch to light mode">
        <i class="fa-solid fa-moon"></i>
      </button>
      <button type="button" class="theme-toggle" id="themeToggleMobile" aria-label="Switch to light mode">
        <i class="fa-solid fa-moon"></i>
      </button>
    `;
    localStorage.clear();
    document.body.classList.remove('light-mode');
  });

  test('click toggles light-mode class', () => {
    initThemeToggle('themeToggle');
    const btn = document.getElementById('themeToggle');
    expect(document.body.classList.contains('light-mode')).toBe(false);
    btn.click();
    expect(document.body.classList.contains('light-mode')).toBe(true);
    expect(localStorage.getItem('theme')).toBe('light');
  });
});

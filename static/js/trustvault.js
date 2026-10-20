/**
 * TrustVault Precision Frontend Interaction Engine (v2.0)
 * Handles:
 *  - Persistent Dark / Light Theme Engine
 *  - Responsive Mobile Navigation Drawer
 *  - Password Visibility Toggles
 *  - Drag & Drop File Upload Zone
 *  - Flash Alert Auto-Dismissal
 *  - Accessible Copy-to-Clipboard & Tooltips
 *  - CSRF Token Utilities
 */

(() => {
    'use strict';

    // -------------------------------------------------------------------------
    // 1. THEME ENGINE INITIALIZATION (Executes immediately to avoid flash of light)
    // -------------------------------------------------------------------------
    const THEME_KEY = 'trustvault-theme';

    function getPreferredTheme() {
        const storedTheme = localStorage.getItem(THEME_KEY);
        if (storedTheme) {
            return storedTheme;
        }
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.documentElement.setAttribute('data-bs-theme', theme);
        localStorage.setItem(THEME_KEY, theme);

        const toggleBtn = document.getElementById('tvThemeToggle');
        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                if (theme === 'dark') {
                    icon.className = 'bi bi-sun-fill text-warning';
                    toggleBtn.setAttribute('title', 'Switch to Light Theme');
                    toggleBtn.setAttribute('aria-label', 'Switch to Light Theme');
                } else {
                    icon.className = 'bi bi-moon-stars-fill';
                    toggleBtn.setAttribute('title', 'Switch to Dark Theme');
                    toggleBtn.setAttribute('aria-label', 'Switch to Dark Theme');
                }
            }
        }
    }

    // Apply preferred theme before full DOM rendering
    applyTheme(getPreferredTheme());

    // -------------------------------------------------------------------------
    // 2. DOM CONTENT LOADED EVENT HANDLERS
    // -------------------------------------------------------------------------
    document.addEventListener('DOMContentLoaded', () => {
        // Theme Toggle Click Handler
        const themeToggle = document.getElementById('tvThemeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
                const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
                applyTheme(nextTheme);
            });
        }

        // Mobile Sidebar Drawer
        const mobileToggle = document.getElementById('tvMobileNavToggle');
        const sidebar = document.getElementById('tvSidebar');
        const backdrop = document.getElementById('tvSidebarBackdrop');

        function toggleSidebar(open) {
            if (!sidebar || !backdrop) return;
            if (open) {
                sidebar.classList.add('show');
                backdrop.classList.add('show');
                document.body.style.overflow = 'hidden';
            } else {
                sidebar.classList.remove('show');
                backdrop.classList.remove('show');
                document.body.style.overflow = '';
            }
        }

        if (mobileToggle) {
            mobileToggle.addEventListener('click', () => {
                const isOpen = sidebar.classList.contains('show');
                toggleSidebar(!isOpen);
            });
        }

        if (backdrop) {
            backdrop.addEventListener('click', () => toggleSidebar(false));
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && sidebar && sidebar.classList.contains('show')) {
                toggleSidebar(false);
            }
        });

        // Password Visibility Toggles
        const passwordToggles = document.querySelectorAll('.tv-password-toggle');
        passwordToggles.forEach(toggle => {
            toggle.addEventListener('click', () => {
                const input = toggle.parentElement.querySelector('input');
                if (!input) return;
                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';
                const icon = toggle.querySelector('i');
                if (icon) {
                    icon.className = isPassword ? 'bi bi-eye-slash-fill' : 'bi bi-eye-fill';
                }
            });
        });

        // Drag & Drop File Upload Dropzone
        const dropzones = document.querySelectorAll('.tv-dropzone');
        dropzones.forEach(zone => {
            const fileInput = zone.querySelector('input[type="file"]');
            const titleEl = zone.querySelector('.tv-dropzone-title');
            const descEl = zone.querySelector('.tv-dropzone-desc');

            if (!fileInput) return;

            ['dragenter', 'dragover'].forEach(eventName => {
                zone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    zone.classList.add('dragover');
                });
            });

            ['dragleave', 'drop'].forEach(eventName => {
                zone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    zone.classList.remove('dragover');
                });
            });

            zone.addEventListener('drop', (e) => {
                const dt = e.dataTransfer;
                if (dt && dt.files && dt.files.length > 0) {
                    fileInput.files = dt.files;
                    updateFileLabel(dt.files[0]);
                }
            });

            fileInput.addEventListener('change', () => {
                if (fileInput.files && fileInput.files.length > 0) {
                    updateFileLabel(fileInput.files[0]);
                }
            });

            function updateFileLabel(file) {
                const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
                if (titleEl) {
                    titleEl.textContent = `Selected: ${file.name}`;
                }
                if (descEl) {
                    descEl.innerHTML = `<span class="badge bg-primary text-white me-1">READY</span> Size: ${sizeMb} MB &bull; Type: ${file.type || 'Binary'}`;
                }

                // Client-side pre-flight check (max 25 MB cap)
                const maxBytes = parseInt(fileInput.getAttribute('data-max-size') || (25 * 1024 * 1024), 10);
                if (file.size > maxBytes) {
                    alert(`Selected file (${sizeMb} MB) exceeds maximum allowed size of ${(maxBytes / (1024 * 1024)).toFixed(0)} MB.`);
                    fileInput.value = '';
                    if (titleEl) titleEl.textContent = 'Drag & drop confidential file here, or click to browse';
                    if (descEl) descEl.textContent = 'Supported formats: PDF, DOCX, XLSX, TXT, PNG, JPG (Max 25 MB)';
                }
            }
        });

        // Flash Alert Auto-Dismissal (after 5 seconds for success / info)
        const autoDismissAlerts = document.querySelectorAll('.tv-alert:not(.tv-alert-danger):not(.tv-alert-warning)');
        autoDismissAlerts.forEach(alert => {
            setTimeout(() => {
                alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-6px)';
                setTimeout(() => alert.remove(), 400);
            }, 5000);
        });

        // Copy-to-Clipboard Action Helpers
        const copyButtons = document.querySelectorAll('[data-copy-target]');
        copyButtons.forEach(btn => {
            btn.addEventListener('click', async () => {
                const targetText = btn.getAttribute('data-copy-target');
                if (!targetText) return;

                try {
                    await navigator.clipboard.writeText(targetText);
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<i class="bi bi-check2 text-success me-1"></i> Copied!';
                    setTimeout(() => {
                        btn.innerHTML = originalHtml;
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy to clipboard', err);
                }
            });
        });
    });

    /**
     * Helper to read CSRF Cookie value for AJAX requests
     */
    window.getCookie = function(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    };
})();

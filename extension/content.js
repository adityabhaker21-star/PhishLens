/**
 * PhishLens - Content Script (content.js)
 * Enterprise-Grade Dynamic Modal / Popup & SPA Authentication Detector.
 * Supports:
 * - Direct password inputs
 * - Shadow DOM / Web Components
 * - Embedded iframes (all_frames: true)
 * - Obfuscated/styled password inputs (placeholders, aria-labels, text-security)
 * - Dynamic modals (Re:ANIME, React, Vue, SvelteKit, Tailwind modals)
 * - Real-time focusin, click, mutation, and manual scan triggers
 */

(function () {
  'use strict';

  // Safe check if extension runtime context is valid
  function isContextValid() {
    try {
      return Boolean(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id);
    } catch (e) {
      return false;
    }
  }

  // Safe wrapper for chrome.runtime.sendMessage that never throws when context is invalidated
  function safeSendMessage(message, callback) {
    if (!isContextValid()) return;
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (!isContextValid() || (chrome.runtime && chrome.runtime.lastError)) {
          return;
        }
        if (callback) callback(response);
      });
    } catch (e) {
      // Context invalidated after extension reload - suppress silently
    }
  }

  let observer = null;
  let scanSequence = 0;
  let debounceTimer = null;
  let lastScannedSignature = null;
  let lastScanTime = 0;
  const SCAN_COOLDOWN_MS = 2500;

  /**
   * Recursively query elements across open Shadow DOM boundaries.
   */
  function queryAcrossShadowDOM(root, predicate) {
    let results = [];
    if (!root) return results;

    const elements = root.querySelectorAll ? Array.from(root.querySelectorAll('*')) : [];
    for (const el of elements) {
      if (predicate(el)) {
        results.push(el);
      }
      if (el.shadowRoot) {
        results = results.concat(queryAcrossShadowDOM(el.shadowRoot, predicate));
      }
    }
    return results;
  }

  /**
   * Comprehensive credential/password input matcher.
   * Matches type=password, name/id/placeholder/aria-label containing pass/pwd/pin/credential,
   * masked inputs, and inputs associated with password labels.
   */
  function isCredentialInput(el) {
    if (!el || el.tagName !== 'INPUT') return false;

    const type = (el.getAttribute('type') || el.type || 'text').toLowerCase();
    if (type === 'password') return true;

    // Check common attributes
    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.getAttribute('id') || '').toLowerCase();
    const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();
    const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
    const autocomplete = (el.getAttribute('autocomplete') || '').toLowerCase();

    const passRegex = /pass|pwd|credential|pin|secret|heslo|contraseña|motdepasse/i;
    if (passRegex.test(name) || passRegex.test(id) || passRegex.test(placeholder) || passRegex.test(ariaLabel) || passRegex.test(autocomplete)) {
      return true;
    }

    // Check CSS text-security masking
    try {
      const style = window.getComputedStyle(el);
      const textSec = style.getPropertyValue('-webkit-text-security') || style.getPropertyValue('text-security');
      if (textSec && textSec !== 'none') return true;
    } catch (e) {}

    // Check preceding label or parent container text
    const label = el.closest('label') || (el.labels && el.labels[0]);
    if (label && passRegex.test(label.innerText || '')) {
      return true;
    }

    // Check previous sibling text
    if (el.previousElementSibling && passRegex.test(el.previousElementSibling.innerText || '')) {
      return true;
    }

    return false;
  }

  /**
   * Find all credential/password inputs anywhere in the document or shadow roots.
   */
  function findPasswordInputs() {
    return queryAcrossShadowDOM(document, isCredentialInput);
  }

  /**
   * Check if an element is visibly rendered on the screen.
   */
  function isElementVisible(el) {
    if (!el) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    try {
      const style = window.getComputedStyle(el);
      return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
    } catch (e) {
      return true;
    }
  }

  /**
   * Find enclosing modal, dialog, popup, or auth container.
   */
  function getModalContext(inputEl) {
    if (!inputEl) return { isModal: false, text: '', container: null };

    const modalSelectors = [
      '[role="dialog"]',
      '[role="alertdialog"]',
      '.modal',
      '.popup',
      '.dialog',
      '.overlay',
      '[class*="modal" i]',
      '[class*="popup" i]',
      '[class*="dialog" i]',
      '[class*="auth" i]',
      '[class*="login" i]',
      '[class*="signin" i]',
      '[class*="register" i]',
      '[class*="signup" i]',
      '[id*="modal" i]',
      '[id*="popup" i]',
      '[id*="dialog" i]',
      '[id*="auth" i]',
      '[id*="login" i]',
      '[id*="signin" i]',
      '[id*="register" i]',
      '[id*="signup" i]'
    ];

    for (const sel of modalSelectors) {
      const container = inputEl.closest(sel);
      if (container) {
        const text = (container.innerText || '').replace(/\s+/g, ' ').trim();
        return { isModal: true, text: text.slice(0, 1500), container: container };
      }
    }

    const form = inputEl.closest('form');
    if (form) {
      const text = (form.innerText || '').replace(/\s+/g, ' ').trim();
      return { isModal: false, text: text.slice(0, 1500), container: form };
    }

    const parent = inputEl.parentElement ? inputEl.parentElement.parentElement : null;
    if (parent) {
      const text = (parent.innerText || '').replace(/\s+/g, ' ').trim();
      return { isModal: false, text: text.slice(0, 800), container: parent };
    }

    return { isModal: false, text: '', container: null };
  }

  function getFaviconUrl() {
    const iconLink = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
    if (iconLink && iconLink.getAttribute('href')) {
      try {
        return new URL(iconLink.getAttribute('href'), window.location.href).href;
      } catch (e) {}
    }
    try {
      return new URL('/favicon.ico', window.location.origin).href;
    } catch (e) {
      return window.location.origin + '/favicon.ico';
    }
  }

  function getExternalLinkRatio() {
    const links = Array.from(document.querySelectorAll('a[href]'));
    let totalLinks = 0;
    let externalLinks = 0;
    const currentHost = window.location.hostname.toLowerCase();

    for (const a of links) {
      const rawHref = a.getAttribute('href');
      if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:') || rawHref.startsWith('mailto:')) {
        continue;
      }
      try {
        const u = new URL(rawHref, window.location.href);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
          totalLinks++;
          if (u.hostname.toLowerCase() !== currentHost) {
            externalLinks++;
          }
        }
      } catch (e) {}
    }

    return totalLinks > 0 ? Number((externalLinks / totalLinks).toFixed(2)) : 0.0;
  }

  /**
   * Collect all password-bearing forms and dynamic modal credential sections.
   */
  function collectPasswordForms() {
    if (!isContextValid()) return [];
    try {
      const passwordForms = [];
      const processedContainers = new Set();
      const pwInputs = findPasswordInputs();

      pwInputs.forEach((pw) => {
        try {
          const formEl = pw.closest('form');
          const container = formEl || getModalContext(pw).container || pw.parentElement;

          if (container && processedContainers.has(container)) {
            return;
          }
          if (container) {
            processedContainers.add(container);
          }

          let action = formEl ? formEl.getAttribute('action') : null;
          if (!action || action.trim() === '') {
            action = window.location.href;
          } else {
            try {
              action = new URL(action, window.location.href).href;
            } catch (e) {
              action = window.location.href;
            }
          }

          const searchRoot = container || document;
          const inputs = Array.from(searchRoot.querySelectorAll('input, select, textarea'));
          const inputNames = inputs
            .map((i) => i.name || i.id || i.getAttribute('placeholder') || i.type)
            .filter((val) => typeof val === 'string' && val.trim().length > 0);

          passwordForms.push({
            action: action,
            has_password: true,
            input_names: inputNames,
            is_modal: !formEl || (container && container !== formEl)
          });
        } catch (inner) {}
      });

      return passwordForms;
    } catch (e) {
      return [];
    }
  }

  /**
   * Build complete inspection payload prioritizing modal context text.
   */
  function buildPayload(activePwInput) {
    const pwInputs = findPasswordInputs();
    const primaryInput = activePwInput || pwInputs[0] || null;
    const modalCtx = getModalContext(primaryInput);

    const modalPrefix = modalCtx.text ? `[ACTIVE AUTH MODAL]: ${modalCtx.text}\n` : '';
    const bodyText = (document.body ? document.body.innerText : '')
      .replace(/\s+/g, ' ')
      .trim();

    const textSnippet = (modalPrefix + bodyText).slice(0, 1500);
    const forms = collectPasswordForms();
    const externalLinkRatio = getExternalLinkRatio();
    const faviconUrl = getFaviconUrl();
    const iframeCount = document.querySelectorAll('iframe').length;

    const payload = {
      url: window.location.href,
      title: document.title || '',
      text_snippet: textSnippet,
      forms: forms,
      external_link_ratio: externalLinkRatio,
      favicon_url: faviconUrl,
      meta: {
        https: window.location.protocol === 'https:',
        iframe_count: iframeCount,
        has_modal: modalCtx.isModal
      }
    };

    return payload;
  }

  /**
   * Main scan trigger with signature deduplication.
   */
  function executeScan(triggerSource = 'auto', activeInput = null, callback = null) {
    if (!isContextValid()) return;
    const pwInputs = findPasswordInputs();
    if (pwInputs.length === 0) {
      if (callback) callback({ success: false, reason: 'No password inputs found' });
      return;
    }

    try {
      if (isContextValid() && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['phishlens_paused'], (result) => {
          if (!isContextValid()) return;
          if (result && result.phishlens_paused === true) {
            console.log('[PhishLens] Protection is paused by user. Skipping scan.');
            if (callback) callback({ success: false, reason: 'Protection paused' });
            return;
          }
          performScan(triggerSource, activeInput, callback);
        });
      } else {
        performScan(triggerSource, activeInput, callback);
      }
    } catch (e) {
      performScan(triggerSource, activeInput, callback);
    }
  }

  function performScan(triggerSource, activeInput, callback) {
    if (!isContextValid()) return;
    try {
      const payload = buildPayload(activeInput);
      const signature = JSON.stringify(payload);
      const sequence = ++scanSequence;
      const pageUrl = window.location.href;
      const now = Date.now();

      if (triggerSource === 'mutation' && signature === lastScannedSignature && (now - lastScanTime < SCAN_COOLDOWN_MS)) {
        if (callback) callback({ success: true, data: window.__phishLensScanResult, cached: true });
        return;
      }

      lastScannedSignature = signature;
      lastScanTime = now;

      console.log(`[PhishLens] Auth form detected via [${triggerSource}]. Dispatching scan payload:`, payload);

      safeSendMessage(
        {
          action: 'ANALYZE_PAGE',
          payload: payload,
          force: triggerSource === 'manual_popup_rescan'
        },
        (response) => {
          if (sequence !== scanSequence || pageUrl !== window.location.href) return;
          if (response && response.success && response.data) {
            console.log('[PhishLens] Scan response received:', response.data);
            window.__phishLensScanResult = response.data;
            if (window.PhishLensOverlay) {
              window.PhishLensOverlay.show(response.data);
              if (response.explanation) window.PhishLensOverlay.updateExplanation(response.explanation);
            }
            if (callback) callback({ success: true, data: response.data });
          } else {
            if (callback) callback({ success: false, response });
          }
        }
      );
    } catch (err) {
      console.debug('[PhishLens] Scan error handled gracefully:', err);
      if (callback) callback({ success: false, error: err.message });
    }
  }

  /**
   * Listen for user interactions that trigger or focus authentication popups.
   */
  function setupInteractionListeners() {
    // 1. Focusin on any password or auth input
    document.addEventListener(
      'focusin',
      (e) => {
        if (!isContextValid()) return;
        const target = e.target;
        if (!target) return;
        if (isCredentialInput(target)) {
          console.log('[PhishLens] Credential input focused by user. Triggering immediate scan.');
          executeScan('focus', target);
        }
      },
      true
    );

    // 2. Click anywhere on page: check if a modal or input was activated
    document.addEventListener(
      'click',
      (e) => {
        if (!isContextValid()) return;
        const target = e.target ? e.target.closest('button, a, [role="button"], input, div') : null;
        if (!target) return;

        // If clicking an input directly
        if (isCredentialInput(target)) {
          executeScan('click_input', target);
          return;
        }

        const text = (target.innerText || target.textContent || '').toLowerCase();
        const authKeywords = ['sign in', 'login', 'log in', 'create account', 'register', 'join', 'sign up'];
        const isAuthButton = authKeywords.some((kw) => text.includes(kw));

        if (isAuthButton) {
          // Dynamic modals mount in 50-300ms
          [100, 300, 600].forEach((delay) => {
            setTimeout(() => {
              if (!isContextValid()) return;
              const pwInputs = findPasswordInputs();
              if (pwInputs.length > 0) {
                executeScan('modal_click', pwInputs[0]);
              }
            }, delay);
          });
        }
      },
      true
    );
  }

  /**
   * Continuous MutationObserver to detect dynamically injected auth modals.
   */
  function initObserver() {
    if (!isContextValid()) return;
    setupInteractionListeners();

    // Check immediately on load
    if (findPasswordInputs().length > 0) {
      executeScan('initial_load');
    }

    observer = new MutationObserver(() => {
      if (!isContextValid()) {
        if (observer) {
          try { observer.disconnect(); } catch (e) {}
          observer = null;
        }
        return;
      }
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (!isContextValid()) return;
        const pwInputs = findPasswordInputs();
        if (pwInputs.length > 0) {
          const hasVisible = pwInputs.some(isElementVisible);
          if (hasVisible) {
            executeScan('mutation');
          }
        }
      }, 200);
    });

    try {
      observer.observe(document.documentElement || document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class', 'style', 'hidden', 'aria-hidden', 'action', 'type', 'name', 'autocomplete']
      });
    } catch (e) {}

    // Run overlay neutralizer on startup and periodic sweep
    neutralizeClickjackOverlays();
    const overlayInterval = setInterval(() => {
      if (!isContextValid()) {
        clearInterval(overlayInterval);
        return;
      }
      neutralizeClickjackOverlays();
    }, 3000);
  }

  // ============================================================================
  // FEATURE 3: Anti-Redirect & Rogue Popunder Shield (Client-side)
  // ============================================================================
  const ROGUE_KEYWORDS = [
    'parimatch', '1xbet', 'betway', 'bet365', 'melbet', 'mostbet',
    'pin-up', 'pinup', 'vulkan', 'linebet', 'casino', 'gambling',
    'slots', 'poker', 'betting', 'propellerads', 'adcash', 'exoclick',
    'popcash', 'popads', 'onclickads', 'hilltopads', 'clickadu',
    'trafficjunky', 'adkeeper', 'onclickprediction', 'syndication.exoclick'
  ];

  function isRogueDestinationUrl(url) {
    if (!url || typeof url !== 'string') return false;
    const urlLower = url.toLowerCase();
    try {
      const parsed = new URL(url, window.location.href);
      const host = parsed.hostname.toLowerCase();
      if (!host || host === window.location.hostname.toLowerCase()) return false;

      // Check keywords
      if (ROGUE_KEYWORDS.some(kw => host.includes(kw))) {
        return true;
      }
      // Check high abuse TLD with tracking parameters
      const highRiskTlds = ['.top', '.click', '.buzz', '.icu', '.monster', '.cfd', '.rest', '.skin'];
      if (highRiskTlds.some(tld => host.endsWith(tld)) && (urlLower.includes('aff') || urlLower.includes('click') || urlLower.includes('track') || urlLower.includes('popunder') || urlLower.includes('ref='))) {
        return true;
      }
    } catch (e) {}
    return false;
  }

  function showShieldToast(message) {
    let toast = document.getElementById('phishlens-shield-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'phishlens-shield-toast';
      toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-left: 4px solid #ef4444;
        border-radius: 8px;
        padding: 12px 16px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        gap: 10px;
        transition: opacity 0.3s ease, transform 0.3s ease;
        opacity: 0;
        transform: translateY(12px);
        pointer-events: none;
      `;
      document.body.appendChild(toast);
    }

    toast.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.2" style="flex-shrink: 0;">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01" />
      </svg>
      <div>
        <div style="font-weight: 700; color: #ffffff; font-size: 12px;">PhishLens Anti-Redirect Shield</div>
        <div style="color: #cbd5e1; font-size: 11px;">${message}</div>
      </div>
    `;

    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';

    setTimeout(() => {
      if (toast) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(12px)';
      }
    }, 3800);
  }

  function neutralizeClickjackOverlays() {
    try {
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const candidates = document.querySelectorAll('a, div, span, section');

      for (const el of candidates) {
        if (el.id && el.id.startsWith('phishlens-')) continue;
        const rect = el.getBoundingClientRect();
        if (rect.width >= vw * 0.80 && rect.height >= vh * 0.80) {
          const style = window.getComputedStyle(el);
          const isFixed = style.position === 'fixed' || style.position === 'absolute';
          const isTransparent = style.opacity === '0' || style.backgroundColor === 'rgba(0, 0, 0, 0)' || style.backgroundColor === 'transparent';
          const highZ = parseInt(style.zIndex, 10) > 500;

          if (isFixed && isTransparent && highZ) {
            if (el.tagName === 'A' && el.href) {
              if (isRogueDestinationUrl(el.href)) {
                console.log('[PhishLens Content] Neutralized invisible clickjack overlay link:', el.href);
                el.style.pointerEvents = 'none';
                el.remove();
                showShieldToast('Neutralized invisible popunder overlay on page.');
              }
            }
          }
        }
      }
    } catch (e) {}
  }

  // Intercept click on links targeting rogue betting/popunder destinations
  document.addEventListener('click', (e) => {
    if (!isContextValid()) return;
    const anchor = e.target ? e.target.closest('a') : null;
    if (anchor && anchor.href && isRogueDestinationUrl(anchor.href)) {
      e.preventDefault();
      e.stopPropagation();
      console.warn('[PhishLens Content] Intercepted rogue link click:', anchor.href);

      safeSendMessage({
        action: 'REPORT_ROUGE_REDIRECT',
        url: anchor.href,
        opener: window.location.href
      });

      showShieldToast('Blocked Rogue Popunder (' + (new URL(anchor.href).hostname || 'Untrusted') + ')');

      if (isContextValid() && chrome.runtime && chrome.runtime.getURL) {
        try {
          const interstitialUrl = chrome.runtime.getURL('interstitial.html') +
            '?url=' + encodeURIComponent(anchor.href) +
            '&opener=' + encodeURIComponent(window.location.href) +
            '&reasons=' + encodeURIComponent(JSON.stringify(['Rogue popunder link intercepted on page']));

          window.open(interstitialUrl, '_blank');
        } catch (e) {}
      }
    }
  }, true);

  // Listen for blocked popunder events dispatched from shield_main.js in the MAIN world
  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'PHISHLENS_POPUNDER_BLOCKED') {
      const blockedUrl = event.data.url;
      let hostname = 'Untrusted Destination';
      try {
        hostname = new URL(blockedUrl).hostname;
      } catch (e) {}

      showShieldToast('Blocked Rogue Popunder (' + hostname + ')');

      safeSendMessage({
        action: 'REPORT_ROUGE_REDIRECT',
        url: blockedUrl,
        opener: window.location.href,
        reason: event.data.reason || 'Rogue popunder blocked'
      });
    }
  });

  // Listen for messages from service worker and popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.action === 'EXPLAIN_RESULT') {
      if (!window.__phishLensScanResult || message.scan_id !== window.__phishLensScanResult.scan_id) return false;
      console.log('[PhishLens] Asynchronous AI explanation received:', message.explanation);
      if (window.PhishLensOverlay) {
        window.PhishLensOverlay.updateExplanation(message.explanation);
      }
      sendResponse({ received: true });
    } else if (message && message.action === 'GET_PAGE_SCAN') {
      const pwInputs = findPasswordInputs();
      sendResponse({
        hasPasswordForm: pwInputs.length > 0,
        scan: window.__phishLensScanResult || null
      });
    } else if (message && message.action === 'TRIGGER_MANUAL_SCAN') {
      const pwInputs = findPasswordInputs();
      if (pwInputs.length > 0) {
        executeScan('manual_popup_rescan', pwInputs[0], (scanResult) => {
          sendResponse({ triggered: true, scan: scanResult ? scanResult.data : null });
        });
      } else {
        sendResponse({ triggered: false, reason: 'No password inputs found' });
      }
    }
    return true; // Keep sendResponse open
  });

  // Expose inspection helper for DevTools debugging
  window.__phishLensGetPayload = buildPayload;
  window.__phishLensFindPasswords = findPasswordInputs;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initObserver);
  } else {
    initObserver();
  }
})();

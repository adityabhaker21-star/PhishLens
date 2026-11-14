/**
 * PhishLens - Content Script (content.js)
 * Detects password forms, collects privacy-preserving page structure signals,
 * and communicates with the background service worker.
 */

(function () {
  'use strict';

  let hasScanned = false;
  let observer = null;
  let debounceTimer = null;

  function hasPasswordInput() {
    return document.querySelector('input[type="password"]') !== null;
  }

  function getFaviconUrl() {
    const iconLink = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
    if (iconLink && iconLink.getAttribute('href')) {
      try {
        return new URL(iconLink.getAttribute('href'), window.location.href).href;
      } catch (e) {
        // Fallback
      }
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
      } catch (e) {
        // Invalid URL, skip
      }
    }

    return totalLinks > 0 ? Number((externalLinks / totalLinks).toFixed(2)) : 0.0;
  }

  function collectPasswordForms() {
    const passwordForms = [];
    const forms = Array.from(document.querySelectorAll('form'));

    // Check standard forms
    forms.forEach((form) => {
      const pw = form.querySelector('input[type="password"]');
      if (pw) {
        let action = form.getAttribute('action');
        if (!action || action.trim() === '') {
          action = window.location.href;
        } else {
          try {
            action = new URL(action, window.location.href).href;
          } catch (e) {
            action = window.location.href;
          }
        }

        // Privacy rule: Collect input names / IDs / types ONLY, never user-entered values
        const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
        const inputNames = inputs
          .map((i) => i.name || i.id || i.type)
          .filter((val) => typeof val === 'string' && val.trim().length > 0);

        passwordForms.push({
          action: action,
          has_password: true,
          input_names: inputNames
        });
      }
    });

    // Check orphan password fields not contained in a <form>
    const orphanPwInputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(
      (pw) => !pw.closest('form')
    );
    if (orphanPwInputs.length > 0 && passwordForms.length === 0) {
      const allInputs = Array.from(document.querySelectorAll('input, select, textarea'));
      const inputNames = allInputs
        .map((i) => i.name || i.id || i.type)
        .filter((val) => typeof val === 'string' && val.trim().length > 0);

      passwordForms.push({
        action: window.location.href,
        has_password: true,
        input_names: inputNames
      });
    }

    return passwordForms;
  }

  function buildPayload() {
    const bodyText = (document.body ? document.body.innerText : '')
      .replace(/\s+/g, ' ')
      .trim();

    const textSnippet = bodyText.slice(0, 1500);
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
        iframe_count: iframeCount
      }
    };

    return payload;
  }

  function executeScan() {
    if (hasScanned) return;
    if (!hasPasswordInput()) return;

    hasScanned = true;
    const payload = buildPayload();

    console.log('[PhishLens] Password form detected. Dispatching scan payload:', payload);

    try {
      chrome.runtime.sendMessage(
        {
          action: 'ANALYZE_PAGE',
          payload: payload
        },
        (response) => {
          if (chrome.runtime.lastError) {
            // Fail open: log and show nothing
            console.debug('[PhishLens] Fail open (backend/service worker):', chrome.runtime.lastError.message);
            return;
          }

          if (response && response.success && response.data) {
            console.log('[PhishLens] Scan response received:', response.data);
            if (window.PhishLensOverlay) {
              window.PhishLensOverlay.show(response.data);
            }
          }
        }
      );
    } catch (err) {
      console.debug('[PhishLens] Fail open on exception:', err);
    }
  }

  function initObserver() {
    // Initial check
    if (hasPasswordInput()) {
      executeScan();
      return;
    }

    // Watch for dynamically loaded login forms (e.g. SPAs, dialogs, late hydrates)
    observer = new MutationObserver(() => {
      if (hasScanned) {
        if (observer) observer.disconnect();
        return;
      }

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (hasPasswordInput()) {
          executeScan();
          if (observer) observer.disconnect();
        }
      }, 350);
    });

    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true
    });
  }

  // Listen for asynchronous LLM explanation pushed from service worker
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.action === 'EXPLAIN_RESULT') {
      console.log('[PhishLens] Asynchronous AI explanation received:', message.explanation);
      if (window.PhishLensOverlay) {
        window.PhishLensOverlay.updateExplanation(message.explanation);
      }
      sendResponse({ received: true });
    }
    return true;
  });

  // Expose inspection helper for DevTools debugging
  window.__phishLensGetPayload = buildPayload;

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initObserver);
  } else {
    initObserver();
  }
})();

/**
 * PhishLens - Warning Overlay & Banner (overlay.js)
 * Mounts in a Shadow DOM to isolate styles from target webpage CSS.
 */

(function () {
  'use strict';

  // Prevent double injection
  if (window.PhishLensOverlay) {
    return;
  }

  let hostElement = null;
  let shadowRoot = null;
  let currentScan = null;

  const STYLES = `
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Top Warning Banner (Score 30-59: Suspicious) */
    .phishlens-banner {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: #fefce8;
      border-bottom: 2px solid #eab308;
      color: #713f12;
      padding: 12px 20px;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.12);
      display: flex;
      flex-direction: column;
      gap: 8px;
      animation: phishlens-slide-down 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes phishlens-slide-down {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }

    .banner-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .banner-title-area {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .banner-icon {
      width: 24px;
      height: 24px;
      color: #ca8a04;
      flex-shrink: 0;
    }

    .banner-title {
      font-size: 15px;
      font-weight: 700;
      color: #854d0e;
    }

    .banner-badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 9999px;
      background: #fef08a;
      border: 1px solid #facc15;
      font-size: 12px;
      font-weight: 600;
      color: #854d0e;
    }

    .banner-reasons {
      padding-left: 34px;
      font-size: 13px;
      line-height: 1.5;
      color: #713f12;
    }

    .banner-reasons li {
      margin-bottom: 4px;
    }

    .banner-explanation {
      margin-left: 34px;
      padding: 8px 12px;
      background: rgba(254, 240, 138, 0.5);
      border-left: 3px solid #eab308;
      border-radius: 4px;
      font-size: 12px;
      color: #854d0e;
    }

    .banner-close-btn {
      background: transparent;
      border: none;
      color: #854d0e;
      cursor: pointer;
      font-size: 18px;
      font-weight: bold;
      padding: 4px 8px;
      border-radius: 4px;
      transition: background 0.15s ease;
    }

    .banner-close-btn:hover {
      background: #fef08a;
    }

    /* Full-Page Red Danger Overlay (Score >= 60: Danger) */
    .phishlens-overlay-backdrop {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      width: 100vw;
      height: 100vh;
      z-index: 2147483647;
      background: rgba(15, 23, 42, 0.88);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      animation: phishlens-fade-in 0.25s ease-out;
    }

    @keyframes phishlens-fade-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .danger-card {
      background: #ffffff;
      color: #0f172a;
      width: 100%;
      max-width: 580px;
      border-radius: 14px;
      border-top: 6px solid #dc2626;
      box-shadow: 0 25px 50px -12px rgba(220, 38, 38, 0.25), 0 10px 30px rgba(0, 0, 0, 0.4);
      padding: 28px 32px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      animation: phishlens-card-zoom 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes phishlens-card-zoom {
      from { transform: scale(0.92); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    .danger-header {
      display: flex;
      align-items: flex-start;
      gap: 16px;
    }

    .danger-icon-wrapper {
      width: 52px;
      height: 52px;
      border-radius: 12px;
      background: #fee2e2;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .danger-icon-wrapper svg {
      width: 32px;
      height: 32px;
      color: #dc2626;
    }

    .danger-title-area {
      flex: 1;
    }

    .danger-title {
      font-size: 22px;
      font-weight: 800;
      color: #991b1b;
      letter-spacing: -0.02em;
      line-height: 1.2;
    }

    .danger-subtitle {
      font-size: 13px;
      color: #64748b;
      margin-top: 4px;
      word-break: break-all;
    }

    .score-badge-row {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 4px;
    }

    .score-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #b91c1c;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 13px;
    }

    .score-bar-bg {
      flex: 1;
      height: 8px;
      background: #fee2e2;
      border-radius: 4px;
      overflow: hidden;
    }

    .score-bar-fill {
      height: 100%;
      background: #dc2626;
      width: 0%;
      transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* Reasons Section */
    .danger-section-title {
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #64748b;
      margin-bottom: 6px;
    }

    .reasons-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .reasons-list li {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 13px;
      line-height: 1.45;
      color: #1e293b;
      background: #f8fafc;
      padding: 8px 12px;
      border-radius: 6px;
      border-left: 3px solid #ef4444;
    }

    .reason-bullet {
      color: #ef4444;
      font-weight: bold;
      line-height: 1;
      margin-top: 2px;
    }

    /* LLM Explanation Box (Layout-stable placeholder) */
    .explanation-container {
      min-height: 68px;
      background: #f1f5f9;
      border-radius: 8px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      transition: all 0.2s ease;
    }

    .explanation-container.has-content {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
    }

    .analysing-pulse {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      color: #64748b;
      font-weight: 500;
    }

    .analysing-spinner {
      width: 14px;
      height: 14px;
      border: 2px solid #cbd5e1;
      border-top-color: #3b82f6;
      border-radius: 50%;
      animation: phishlens-spin 0.8s linear infinite;
    }

    @keyframes phishlens-spin {
      to { transform: rotate(360deg); }
    }

    .ai-advice-line {
      font-size: 13px;
      font-weight: 600;
      color: #0f172a;
      line-height: 1.4;
    }

    .ai-reasons-summary {
      margin-top: 6px;
      font-size: 12px;
      color: #475569;
      line-height: 1.4;
    }

    /* Action Buttons */
    .danger-actions {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
      margin-top: 8px;
    }

    .btn-safety {
      width: 100%;
      padding: 14px 20px;
      background: #dc2626;
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(220, 38, 38, 0.3);
      transition: background 0.15s ease, transform 0.1s ease;
    }

    .btn-safety:hover {
      background: #b91c1c;
      transform: translateY(-1px);
    }

    .btn-safety:focus {
      outline: 3px solid #f87171;
      outline-offset: 2px;
    }

    .btn-continue {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 12px;
      text-decoration: underline;
      cursor: pointer;
      padding: 4px 8px;
      transition: color 0.15s ease;
    }

    .btn-continue:hover {
      color: #0f172a;
    }
  `;

  function isBypassed() {
    try {
      return sessionStorage.getItem('phishlens_bypassed_' + window.location.hostname) === 'true';
    } catch (e) {
      return false;
    }
  }

  function setBypassed() {
    try {
      sessionStorage.setItem('phishlens_bypassed_' + window.location.hostname, 'true');
    } catch (e) {
      console.warn('PhishLens: Failed to set sessionStorage bypass', e);
    }
  }

  function ensureShadowRoot() {
    if (!hostElement || !document.contains(hostElement)) {
      hostElement = document.createElement('div');
      hostElement.id = 'phishlens-root';
      hostElement.style.cssText = 'all: initial !important; position: static !important;';
      shadowRoot = hostElement.attachShadow({ mode: 'open' });

      const styleTag = document.createElement('style');
      styleTag.textContent = STYLES;
      shadowRoot.appendChild(styleTag);

      document.documentElement.appendChild(hostElement);
    }
    return shadowRoot;
  }

  function hide() {
    if (hostElement && hostElement.parentNode) {
      hostElement.parentNode.removeChild(hostElement);
    }
    hostElement = null;
    shadowRoot = null;
    currentScan = null;
  }

  function renderSuspiciousBanner(scan) {
    const root = ensureShadowRoot();
    // Clear previous banner/overlay content except style tag
    const existing = root.querySelector('.phishlens-banner, .phishlens-overlay-backdrop');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = 'phishlens-banner';

    const topReasons = (scan.signals || []).slice(0, 2).map(s => s.detail || s.id);
    const reasonsHtml = topReasons.length > 0
      ? `<ul class="banner-reasons">${topReasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`
      : '';

    banner.innerHTML = `
      <div class="banner-header">
        <div class="banner-title-area">
          <svg class="banner-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span class="banner-title">PhishLens Warning: Suspicious Login Page</span>
          <span class="banner-badge">Risk Score: ${Math.round(scan.score)}/100</span>
        </div>
        <button class="banner-close-btn" title="Dismiss warning">&times;</button>
      </div>
      ${reasonsHtml}
      <div class="banner-explanation" id="phishlens-banner-exp" style="display: none;"></div>
    `;

    banner.querySelector('.banner-close-btn').addEventListener('click', () => {
      banner.remove();
    });

    root.appendChild(banner);
  }

  function renderDangerOverlay(scan) {
    const root = ensureShadowRoot();
    const existing = root.querySelector('.phishlens-banner, .phishlens-overlay-backdrop');
    if (existing) existing.remove();

    const backdrop = document.createElement('div');
    backdrop.className = 'phishlens-overlay-backdrop';

    const topReasons = (scan.signals || []).slice(0, 3).map(s => s.detail || s.id);
    const reasonsHtml = topReasons.length > 0
      ? topReasons.map(r => `<li><span class="reason-bullet">&#9679;</span> <span>${escapeHtml(r)}</span></li>`).join('')
      : '<li><span class="reason-bullet">&#9679;</span> <span>Multiple high-risk phishing indicators detected.</span></li>';

    backdrop.innerHTML = `
      <div class="danger-card" role="alertdialog" aria-modal="true" aria-labelledby="phishlens-danger-title">
        <div class="danger-header">
          <div class="danger-icon-wrapper">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div class="danger-title-area">
            <h1 class="danger-title" id="phishlens-danger-title">Phishing Threat Detected</h1>
            <p class="danger-subtitle">${escapeHtml(window.location.hostname)}</p>
            <div class="score-badge-row">
              <span class="score-badge">
                <span>Score:</span>
                <span id="phishlens-score-counter">0</span>/100
              </span>
              <div class="score-bar-bg">
                <div class="score-bar-fill" id="phishlens-score-bar"></div>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div class="danger-section-title">Key Detection Signals</div>
          <ul class="reasons-list">
            ${reasonsHtml}
          </ul>
        </div>

        <div class="explanation-container" id="phishlens-explanation-box">
          <div class="analysing-pulse" id="phishlens-analysing-status">
            <div class="analysing-spinner"></div>
            <span>Analysing page context with AI...</span>
          </div>
        </div>

        <div class="danger-actions">
          <button class="btn-safety" id="phishlens-btn-safety">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Go back to safety (Recommended)
          </button>
          <button class="btn-continue" id="phishlens-btn-continue">
            I understand the risk, continue anyway
          </button>
        </div>
      </div>
    `;

    root.appendChild(backdrop);

    // Score fill animation
    const scoreVal = Math.min(100, Math.max(0, Math.round(scan.score || 0)));
    const counterEl = backdrop.querySelector('#phishlens-score-counter');
    const barFillEl = backdrop.querySelector('#phishlens-score-bar');

    setTimeout(() => {
      if (barFillEl) barFillEl.style.width = scoreVal + '%';
      animateCounter(counterEl, 0, scoreVal, 400);
    }, 50);

    // Event listeners
    const safetyBtn = backdrop.querySelector('#phishlens-btn-safety');
    const continueBtn = backdrop.querySelector('#phishlens-btn-continue');

    safetyBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      // Check if running on test_preview.html or explicitly in test mode
      const isTestEnv = window.__phishLensIsTest ||
                        window.location.href.includes('test_preview.html') ||
                        window.location.protocol === 'file:';

      if (isTestEnv) {
        console.log('[PhishLens] "Go back to safety" clicked in test environment. Dismissing overlay.');
        hide();

        // Show friendly in-page feedback for test bench
        const toast = document.createElement('div');
        toast.id = 'phishlens-safety-toast';
        toast.style.cssText = 'position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: #38bdf8; border: 1px solid #0284c7; padding: 12px 18px; border-radius: 8px; font-size: 13px; font-weight: 600; z-index: 2147483647; box-shadow: 0 10px 25px rgba(0,0,0,0.3); font-family: sans-serif;';
        toast.innerHTML = '&#10003; "Go back to safety" clicked &mdash; on live sites, this returns to previous page or navigates to safety.';
        document.body.appendChild(toast);
        setTimeout(() => { if (toast.parentNode) toast.remove(); }, 3500);

        if (typeof window.log === 'function') {
          window.log('"Go back to safety" action executed successfully.');
        }
        return;
      }

      // Live environment: hide modal immediately so user sees instant response
      hide();

      // Ask extension background worker to navigate or redirect tab
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        try {
          chrome.runtime.sendMessage({ action: 'GO_BACK_TO_SAFETY' });
        } catch (err) {
          console.debug('[PhishLens] Extension message failed:', err);
        }
      }

      // Attempt standard browser history navigation
      if (window.history.length > 1) {
        try {
          window.history.back();
        } catch (err) {}
      }

      // Safety fallback: if history.back did not navigate away (e.g. fresh tab or restricted chrome://), redirect to about:blank
      setTimeout(() => {
        try {
          window.location.replace('about:blank');
        } catch (e) {
          window.location.href = 'about:blank';
        }
      }, 250);
    });

    continueBtn.addEventListener('click', () => {
      setBypassed();
      hide();
    });

    // Keyboard focus on main button
    setTimeout(() => {
      safetyBtn.focus();
    }, 100);
  }

  function animateCounter(element, start, end, duration) {
    if (!element) return;
    const startTime = performance.now();
    function update(time) {
      const elapsed = time - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = Math.floor(start + (end - start) * progress);
      element.textContent = current;
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        element.textContent = end;
      }
    }
    requestAnimationFrame(update);
  }

  function show(scan) {
    currentScan = scan;
    const score = scan && typeof scan.score === 'number' ? scan.score : 0;

    // Gate: Under 30 is safe -> show nothing
    if (score < 30) {
      hide();
      return;
    }

    // Check if user already dismissed/bypassed for this session
    if (isBypassed()) {
      return;
    }

    if (score >= 30 && score <= 59) {
      renderSuspiciousBanner(scan);
    } else if (score >= 60) {
      renderDangerOverlay(scan);
    }
  }

  function updateExplanation(explanation) {
    if (!shadowRoot || !explanation) return;

    // Check banner explanation
    const bannerExp = shadowRoot.querySelector('#phishlens-banner-exp');
    if (bannerExp) {
      const advice = explanation.advice || '';
      bannerExp.innerHTML = `<strong>AI Security Note:</strong> ${escapeHtml(advice)}`;
      bannerExp.style.display = 'block';
    }

    // Check danger overlay explanation box
    const expBox = shadowRoot.querySelector('#phishlens-explanation-box');
    if (expBox) {
      expBox.classList.add('has-content');
      const advice = explanation.advice || 'Do not submit credentials on this page.';
      const reasons = Array.isArray(explanation.reasons) ? explanation.reasons : [];
      const reasonsList = reasons.length > 0
        ? `<div class="ai-reasons-summary">&#8226; ${reasons.map(r => escapeHtml(r)).join('<br>&#8226; ')}</div>`
        : '';

      expBox.innerHTML = `
        <div class="ai-advice-line">${escapeHtml(advice)}</div>
        ${reasonsList}
      `;
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Testing helper
  function test(score = 87) {
    window.__phishLensIsTest = true;
    const mockScan = {
      scan_id: 'test_' + Date.now(),
      score: score,
      verdict: score >= 60 ? 'danger' : (score >= 30 ? 'suspicious' : 'safe'),
      signals: [
        { id: 'brand_mismatch', points: 30, detail: 'Brand Nova Bank claimed but domain does not match official domain' },
        { id: 'lookalike_domain', points: 25, detail: 'Look-alike domain detected: edit distance within 2 of novabank.test' },
        { id: 'form_action_mismatch', points: 20, detail: 'Form action points to collect.test, not this page' }
      ]
    };
    show(mockScan);
    if (score >= 30) {
      setTimeout(() => {
        updateExplanation({
          verdict: score >= 60 ? 'phishing' : 'suspicious',
          confidence: 0.94,
          reasons: [
            'Impersonates Nova Bank on an unauthorized domain.',
            'Credentials will be sent to external endpoint collect.test.',
            'Urgency pressure detected to bypass rational verification.'
          ],
          advice: 'Do not enter your credentials. Go to official novabank.test.'
        });
      }, 1200);
    }
  }

  // Public API
  window.PhishLensOverlay = {
    show,
    updateExplanation,
    hide,
    test,
    isBypassed
  };

})();

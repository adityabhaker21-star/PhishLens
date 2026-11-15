/**
 * PhishLens - Interstitial Warning Page Script (interstitial.js)
 * Displays threat details when a rogue redirect / popunder is intercepted.
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url') || '';
  const openerUrl = urlParams.get('opener') || '';
  const reasonsParam = urlParams.get('reasons') || '[]';
  const category = urlParams.get('category') || 'rogue_popunder';

  const sourceDomainEl = document.getElementById('source-domain');
  const targetDomainEl = document.getElementById('target-domain');
  const reasonsListEl = document.getElementById('reasons-list');
  const btnCloseTab = document.getElementById('btn-close-tab');
  const btnReturnSource = document.getElementById('btn-return-source');
  const btnProceedAnyway = document.getElementById('btn-proceed-anyway');

  // Fill in blocked destination
  if (targetUrl) {
    targetDomainEl.textContent = targetUrl;
    targetDomainEl.title = targetUrl;
  } else {
    targetDomainEl.textContent = 'Unknown suspicious destination';
  }

  // Fill in triggering source
  if (openerUrl) {
    sourceDomainEl.textContent = openerUrl;
    sourceDomainEl.title = openerUrl;
  } else {
    sourceDomainEl.textContent = 'Background Script / Click Hijack Overlay';
  }

  // Parse and display reasons
  let reasons = [];
  try {
    reasons = JSON.parse(reasonsParam);
    if (!Array.isArray(reasons)) {
      reasons = [String(reasons)];
    }
  } catch (e) {
    if (reasonsParam) {
      reasons = [reasonsParam];
    }
  }

  if (reasons.length === 0) {
    if (category === 'betting_popunder') {
      reasons.push('Deceptive betting / gambling network signature detected');
    } else if (category === 'ad_network') {
      reasons.push('Known rogue advertising / popunder network');
    } else {
      reasons.push('Unauthorized cross-origin background navigation');
    }
  }

  reasonsListEl.innerHTML = '';
  reasons.forEach((reason) => {
    const li = document.createElement('li');
    li.className = 'reason-chip';
    li.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
      </svg>
      <span>${escapeHtml(reason)}</span>
    `;
    reasonsListEl.appendChild(li);
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Button 1: Close Tab (Recommended)
  btnCloseTab.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'CLOSE_CURRENT_TAB' }, () => {
      window.close();
    });
  });

  // Button 2: Return to source
  btnReturnSource.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'RETURN_TO_SOURCE', openerUrl: openerUrl }, () => {
      window.close();
    });
  });

  // Button 3: Proceed anyway
  btnProceedAnyway.addEventListener('click', () => {
    const confirmed = window.confirm(
      'SECURITY WARNING:\n\n' +
      'PhishLens blocked this page because it was identified as a rogue redirect or unverified popunder.\n\n' +
      'Opening it may expose you to scams, deceptive betting, phishing forms, or malware.\n\n' +
      'Are you sure you want to proceed anyway?'
    );

    if (confirmed && targetUrl) {
      chrome.runtime.sendMessage({ action: 'ALLOW_AND_PROCEED', url: targetUrl }, () => {
        window.location.replace(targetUrl);
      });
    }
  });
});


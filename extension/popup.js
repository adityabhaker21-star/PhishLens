/**
 * PhishLens - Popup Script (popup.js)
 * Displays the current tab's scan verdict, score, triggered signals, and AI explanation.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scoreNum = document.getElementById('score-num');
  const verdictBadge = document.getElementById('verdict-badge');
  const urlPreview = document.getElementById('url-preview');
  const signalsList = document.getElementById('signals-list');
  const aiBox = document.getElementById('ai-box');
  const aiAdvice = document.getElementById('ai-advice');
  const scanContainer = document.getElementById('scan-container');
  const emptyState = document.getElementById('empty-state');
  const btnRescan = document.getElementById('btn-rescan');
  const btnDashboard = document.getElementById('btn-dashboard');

  let currentTab = null;

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      currentTab = tabs[0];
    }
  } catch (err) {
    console.warn('Failed to query active tab:', err);
  }

  function renderScan(scanEntry) {
    if (!scanEntry || !scanEntry.data) {
      scanContainer.style.display = 'none';
      emptyState.style.display = 'block';
      return;
    }

    const data = scanEntry.data;
    const explanation = scanEntry.explanation;
    const url = scanEntry.url || (currentTab ? currentTab.url : '');

    scanContainer.style.display = 'block';
    emptyState.style.display = 'none';

    // URL preview
    urlPreview.textContent = url;
    urlPreview.title = url;

    // Score & Verdict
    const score = typeof data.score === 'number' ? Math.round(data.score) : 0;
    scoreNum.textContent = data.verdict === 'unknown' ? '—' : score;

    verdictBadge.className = 'verdict-badge';
    if (data.verdict === 'unknown') {
      verdictBadge.textContent = 'Not checked';
      scoreNum.style.color = '#94a3b8';
    } else if (data.verdict === 'danger' || score >= 60) {
      verdictBadge.textContent = 'Danger';
      verdictBadge.classList.add('verdict-danger');
      scoreNum.style.color = '#f87171';
    } else if (data.verdict === 'suspicious' || score >= 30) {
      verdictBadge.textContent = 'Suspicious';
      verdictBadge.classList.add('verdict-suspicious');
      scoreNum.style.color = '#facc15';
    } else {
      verdictBadge.textContent = 'Safe';
      verdictBadge.classList.add('verdict-safe');
      scoreNum.style.color = '#4ade80';
    }

    // Signals
    signalsList.innerHTML = '';
    const signals = Array.isArray(data.signals) ? data.signals : [];
    if (signals.length === 0) {
      const li = document.createElement('li');
      li.className = 'signal-item';
      li.textContent = data.verdict === 'unknown'
        ? 'Analysis unavailable. Check your backend connection and re-scan.'
        : 'No configured risk signals triggered on this page.';
      signalsList.appendChild(li);
    } else {
      signals.forEach((sig) => {
        const li = document.createElement('li');
        li.className = 'signal-item';
        const points = typeof sig.points === 'number' ? `+${sig.points}` : 'Alert';
        const detail = sig.detail || sig.id || 'Unknown signal';
        li.innerHTML = `
          <span class="signal-points">${escapeHtml(points)}</span>
          <span class="signal-detail">${escapeHtml(detail)}</span>
        `;
        signalsList.appendChild(li);
      });
    }

    // AI Explanation & Advice
    if (explanation && (explanation.advice || explanation.reasons)) {
      aiBox.style.display = 'block';
      const adviceText = explanation.advice || '';
      const reasonsList = Array.isArray(explanation.reasons) ? explanation.reasons : [];
      let reasonsHtml = '';
      if (reasonsList.length > 0) {
        reasonsHtml = `<ul style="margin-top: 6px; padding-left: 16px; color: #94a3b8; font-size: 11px;">
          ${reasonsList.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>`;
      }
      aiAdvice.innerHTML = `<div><strong>Recommendation:</strong> ${escapeHtml(adviceText)}</div>${reasonsHtml}`;
    } else {
      aiBox.style.display = 'none';
    }

    // Community Reports Count (Feature 1)
    const reportsCount = typeof data.reports_count === 'number' ? data.reports_count : 0;
    const popupReportsCount = document.getElementById('popup-reports-count');
    if (popupReportsCount) {
      popupReportsCount.textContent = `${reportsCount} user report${reportsCount === 1 ? '' : 's'}`;
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

  // Load initial tab scan
  if (currentTab && currentTab.id) {
    chrome.runtime.sendMessage(
      { action: 'GET_TAB_SCAN', tabId: currentTab.id, url: currentTab.url },
      (res) => {
        if (!chrome.runtime.lastError && res && res.scan && res.scan.data) {
          renderScan(res.scan);
        } else {
          // Fallback: Query content script on active tab directly
          chrome.tabs.sendMessage(currentTab.id, { action: 'GET_PAGE_SCAN' }, (pageRes) => {
            if (!chrome.runtime.lastError && pageRes) {
              if (pageRes.scan) {
                renderScan({ data: pageRes.scan, url: currentTab.url });
              } else if (pageRes.hasPasswordForm) {
                // Trigger real-time scan right now
                chrome.tabs.sendMessage(currentTab.id, { action: 'TRIGGER_MANUAL_SCAN' }, (triggerRes) => {
                  if (triggerRes && triggerRes.scan) {
                    renderScan({ data: triggerRes.scan, url: currentTab.url });
                  } else {
                    renderScan({
                      data: { score: null, verdict: 'unknown', signals: [] },
                      url: currentTab.url
                    });
                  }
                });
              } else {
                renderScan(null);
              }
            } else {
              renderScan(null);
            }
          });
        }
      }
    );
  } else {
    renderScan(null);
  }

  // Load Anti-Redirect Shield stats
  const blockedCountText = document.getElementById('blocked-count-text');
  const shieldBadgeStatus = document.getElementById('shield-badge-status');
  const redirectShieldCard = document.getElementById('redirect-shield-card');

  function updateShieldStats() {
    chrome.runtime.sendMessage({ action: 'GET_BLOCKED_REDIRECTS_STATS' }, (res) => {
      if (res) {
        const count = res.count || 0;
        if (blockedCountText) {
          blockedCountText.textContent = `${count} rogue popunder${count === 1 ? '' : 's'} blocked`;
        }
        if (shieldBadgeStatus) {
          shieldBadgeStatus.textContent = res.shieldActive ? 'ACTIVE' : 'OFF';
          shieldBadgeStatus.style.color = res.shieldActive ? '#38bdf8' : '#94a3b8';
          shieldBadgeStatus.style.background = res.shieldActive ? 'rgba(56, 189, 248, 0.15)' : 'rgba(148, 163, 184, 0.15)';
        }
      }
    });
  }

  updateShieldStats();

  if (redirectShieldCard) {
    redirectShieldCard.style.cursor = 'pointer';
    redirectShieldCard.title = 'Click to toggle Anti-Redirect Shield';
    redirectShieldCard.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'TOGGLE_REDIRECT_SHIELD' }, () => {
        updateShieldStats();
      });
    });
  }

  // Protection Pause/Resume toggle
  const statusToggle = document.getElementById('status-toggle');
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');

  chrome.storage.local.get(['phishlens_paused'], (result) => {
    const isPaused = result && result.phishlens_paused === true;
    updateToggleUI(isPaused);
  });

  function updateToggleUI(isPaused) {
    if (!statusDot || !statusText) return;
    if (isPaused) {
      statusDot.style.background = '#94a3b8';
      statusText.textContent = 'Protection Paused';
      statusToggle.style.opacity = '0.75';
    } else {
      statusDot.style.background = '#22c55e';
      statusText.textContent = 'Shield Active';
      statusToggle.style.opacity = '1';
    }
  }

  if (statusToggle) {
    statusToggle.addEventListener('click', () => {
      chrome.storage.local.get(['phishlens_paused'], (result) => {
        const nextState = !(result && result.phishlens_paused === true);
        chrome.storage.local.set({ phishlens_paused: nextState }, () => {
          updateToggleUI(nextState);
        });
      });
    });
  }

  // Button actions: Re-scan triggers instant in-tab analysis without closing modals
  btnRescan.addEventListener('click', () => {
    if (currentTab && currentTab.id) {
      scoreNum.textContent = '...';
      chrome.tabs.sendMessage(currentTab.id, { action: 'TRIGGER_MANUAL_SCAN' }, (res) => {
        if (!chrome.runtime.lastError && res && res.scan) {
          renderScan({ data: res.scan, url: currentTab.url });
        } else {
          // If tab did not have inputs, do full reload
          chrome.tabs.reload(currentTab.id);
          window.close();
        }
      });
    }
  });

  // Community Reporting Action (Feature 1)
  const btnPopupReport = document.getElementById('btn-popup-report');
  if (btnPopupReport) {
    btnPopupReport.addEventListener('click', () => {
      const targetUrl = (currentTab && currentTab.url) ? currentTab.url : window.location.href;
      btnPopupReport.disabled = true;
      btnPopupReport.textContent = 'Reporting...';
      chrome.runtime.sendMessage({ action: 'REPORT_PHISHING', url: targetUrl }, (res) => {
        if (chrome.runtime.lastError || !res || !res.success || !Number.isInteger(res.data?.reports_count)) {
          btnPopupReport.disabled = false;
          btnPopupReport.textContent = 'Report failed — Retry';
          return;
        }
        const count = res.data.reports_count;
        const popupReportsCount = document.getElementById('popup-reports-count');
        if (popupReportsCount) {
          popupReportsCount.textContent = `${count} user report${count === 1 ? '' : 's'}`;
        }
        btnPopupReport.innerHTML = '&#10003; Reported!';
        btnPopupReport.style.background = '#059669';
      });
    });
  }

  btnDashboard.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:8080/dashboard.html' });
  });
});

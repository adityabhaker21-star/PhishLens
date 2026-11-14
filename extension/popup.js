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
    scoreNum.textContent = score;

    verdictBadge.className = 'verdict-badge';
    if (data.verdict === 'danger' || score >= 60) {
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
      li.innerHTML = '<span class="signal-detail" style="color: #4ade80;">&#10003; No risk signals triggered on this page.</span>';
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
      { action: 'GET_TAB_SCAN', tabId: currentTab.id },
      (res) => {
        if (chrome.runtime.lastError) {
          console.debug('Failed to get tab scan:', chrome.runtime.lastError.message);
          return;
        }
        renderScan(res ? res.scan : null);
      }
    );
  } else {
    renderScan(null);
  }

  // Button actions
  btnRescan.addEventListener('click', () => {
    if (currentTab && currentTab.id) {
      chrome.tabs.reload(currentTab.id);
      window.close();
    }
  });

  btnDashboard.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:8000/events' });
  });
});

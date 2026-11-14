/**
 * PhishLens - Background Service Worker (background.js)
 * Coordinates network requests to FastAPI backend, handles caching in
 * chrome.storage.session, manages badge state, and pushes explanations.
 */

const API_BASE_URL = 'http://localhost:8000';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory mock responses for development/offline testing before backend is live
function getMockAnalyze(payload) {
  const url = (payload && payload.url) ? payload.url.toLowerCase() : '';

  if (url.includes('novabank-kyc-verify.test')) {
    return {
      scan_id: 'mock_fake_' + Date.now(),
      score: 87,
      verdict: 'danger',
      signals: [
        {
          id: 'brand_mismatch',
          points: 30,
          detail: 'Brand Nova Bank claimed but domain does not match official domain'
        },
        {
          id: 'lookalike_domain',
          points: 25,
          detail: 'Look-alike domain detected: edit distance within 2 of novabank.test'
        },
        {
          id: 'form_action_mismatch',
          points: 20,
          detail: 'Password form posts to collect.test, not this site'
        },
        {
          id: 'urgency_language',
          points: 10,
          detail: 'Urgent compliance language detected: KYC expiry / account block'
        }
      ]
    };
  }

  if (url.includes('borderline.test')) {
    return {
      scan_id: 'mock_border_' + Date.now(),
      score: 30,
      verdict: 'suspicious',
      signals: [
        {
          id: 'new_domain',
          points: 15,
          detail: 'Domain registered recently (less than 30 days)'
        },
        {
          id: 'insecure_or_ip',
          points: 15,
          detail: 'Login form served over insecure HTTP connection'
        }
      ]
    };
  }

  if (url.includes('novabank.test')) {
    return {
      scan_id: 'mock_real_' + Date.now(),
      score: 15,
      verdict: 'safe',
      signals: [
        {
          id: 'insecure_or_ip',
          points: 15,
          detail: 'Local test environment running on plain HTTP'
        }
      ]
    };
  }

  // Generic fallback if unknown test domain
  return null;
}

function getMockExplanation(scanId, scan) {
  if (scan && scan.verdict === 'danger') {
    return {
      verdict: 'phishing',
      confidence: 0.94,
      reasons: [
        'Impersonates Nova Bank on an unauthorized domain.',
        'Credentials will be sent to external endpoint collect.test.',
        'Urgency pressure detected to bypass rational verification.'
      ],
      advice: 'Do not enter your credentials. Go to official novabank.test.'
    };
  }

  return {
    verdict: 'suspicious',
    confidence: 0.75,
    reasons: [
      'Domain was registered recently.',
      'Credentials sent over unencrypted HTTP.'
    ],
    advice: 'Verify the identity of this organization before providing credentials.'
  };
}

// Storage helpers
async function getCachedScan(url) {
  try {
    const key = 'cache_' + encodeURIComponent(url);
    const result = await chrome.storage.session.get(key);
    const entry = result[key];
    if (entry && (Date.now() - entry.timestamp < CACHE_TTL_MS)) {
      return entry;
    }
  } catch (err) {
    console.debug('[PhishLens SW] Cache read error:', err);
  }
  return null;
}

async function setCachedScan(url, scanData, explanation = null) {
  try {
    const key = 'cache_' + encodeURIComponent(url);
    const entry = {
      timestamp: Date.now(),
      data: scanData,
      explanation: explanation
    };
    await chrome.storage.session.set({ [key]: entry });
  } catch (err) {
    console.debug('[PhishLens SW] Cache write error:', err);
  }
}

async function setTabScan(tabId, scanData, explanation = null) {
  try {
    const key = 'tab_' + tabId;
    await chrome.storage.session.set({
      [key]: {
        tabId: tabId,
        url: scanData.url,
        data: scanData,
        explanation: explanation,
        updatedAt: Date.now()
      }
    });
  } catch (err) {
    console.debug('[PhishLens SW] Tab scan save error:', err);
  }
}

function updateBadge(tabId, verdict, score) {
  if (!chrome.action) return;

  if (verdict === 'danger') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
  } else if (verdict === 'suspicious') {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#eab308' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

async function fetchAnalyze(payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);

  try {
    const res = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (res.ok) {
      const data = await res.json();
      return data;
    }
  } catch (err) {
    clearTimeout(timer);
    console.debug('[PhishLens SW] /analyze fetch failed:', err.message);
  }

  // Fallback to contract mock if backend is down or not started yet
  return getMockAnalyze(payload);
}

async function fetchExplanation(scanId, url, tabId, scanResult) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);

  let explanation = null;

  try {
    const res = await fetch(`${API_BASE_URL}/explain/${encodeURIComponent(scanId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal
    });

    clearTimeout(timer);

    if (res.ok) {
      explanation = await res.json();
    }
  } catch (err) {
    clearTimeout(timer);
    console.debug('[PhishLens SW] /explain fetch failed:', err.message);
  }

  if (!explanation) {
    // Fallback explanation
    explanation = getMockExplanation(scanId, scanResult);
  }

  if (explanation) {
    // Update cache
    await setCachedScan(url, scanResult, explanation);
    if (tabId) {
      await setTabScan(tabId, scanResult, explanation);
      // Forward to content script
      try {
        chrome.tabs.sendMessage(tabId, {
          action: 'EXPLAIN_RESULT',
          scan_id: scanId,
          explanation: explanation
        });
      } catch (e) {
        console.debug('[PhishLens SW] Forward explanation failed:', e);
      }
    }
  }
}

// Runtime message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  if (message.action === 'ANALYZE_PAGE') {
    const payload = message.payload;
    if (!payload || !payload.url) {
      sendResponse({ success: false, error: 'Empty payload' });
      return true;
    }

    (async () => {
      // 1. Check cache
      const cached = await getCachedScan(payload.url);
      if (cached && cached.data) {
        console.log('[PhishLens SW] Returning cached scan for', payload.url);
        if (tabId) {
          updateBadge(tabId, cached.data.verdict, cached.data.score);
          await setTabScan(tabId, cached.data, cached.explanation);
        }
        sendResponse({ success: true, data: cached.data });

        // Forward cached explanation if available
        if (cached.explanation && tabId) {
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {
              action: 'EXPLAIN_RESULT',
              scan_id: cached.data.scan_id,
              explanation: cached.explanation
            });
          }, 150);
        }
        return;
      }

      // 2. Fetch analysis from backend (or mock fallback)
      const scanResult = await fetchAnalyze(payload);
      if (!scanResult) {
        // Fail open
        sendResponse({ success: false, failOpen: true });
        return;
      }

      // Ensure url is attached
      scanResult.url = payload.url;

      // Update badge & cache
      if (tabId) {
        updateBadge(tabId, scanResult.verdict, scanResult.score);
        await setTabScan(tabId, scanResult, null);
      }
      await setCachedScan(payload.url, scanResult, null);

      // Return initial scan response immediately to display UI
      sendResponse({ success: true, data: scanResult });

      // 3. If score >= 30, asynchronously fetch LLM explanation
      if (scanResult.score >= 30 && scanResult.scan_id) {
        fetchExplanation(scanResult.scan_id, payload.url, tabId, scanResult);
      }
    })();

    return true; // Keep message channel open for async response
  }

  if (message.action === 'GET_TAB_SCAN') {
    (async () => {
      const targetTabId = message.tabId || tabId;
      if (!targetTabId) {
        sendResponse({ scan: null });
        return;
      }
      const key = 'tab_' + targetTabId;
      const res = await chrome.storage.session.get(key);
      sendResponse({ scan: res[key] || null });
    })();
    return true;
  }

  if (message.action === 'GO_BACK_TO_SAFETY') {
    (async () => {
      if (!tabId) {
        sendResponse({ success: false });
        return;
      }
      try {
        if (chrome.tabs && chrome.tabs.goBack) {
          await chrome.tabs.goBack(tabId);
        } else {
          await chrome.tabs.update(tabId, { url: 'about:blank' });
        }
      } catch (err) {
        // If cannot go back (e.g. no back history or security block), redirect tab to about:blank
        try {
          await chrome.tabs.update(tabId, { url: 'about:blank' });
        } catch (e) {
          console.debug('[PhishLens SW] Navigation to safety failed:', e);
        }
      }
      sendResponse({ success: true });
    })();
    return true;
  }

  return false;
});

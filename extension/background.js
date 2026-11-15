/**
 * PhishLens - Background Service Worker (background.js)
 * Coordinates network requests to FastAPI backend, handles caching in
 * chrome.storage.session, manages badge state, and pushes explanations.
 */

const LOCAL_API_BASE_URL = 'http://localhost:8000';
const PUBLIC_API_BASE_URL = 'https://struct-printed-horse-survey.trycloudflare.com';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

async function getApiBaseUrl() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      const custom = await chrome.storage.local.get(['phishlens_api_url']);
      if (custom && custom.phishlens_api_url) {
        return custom.phishlens_api_url;
      }
    } catch (e) {}
  }
  // Try local dev server first, fall back to public Cloudflare HTTPS URL
  try {
    const res = await fetch(`${LOCAL_API_BASE_URL}/`, { method: 'GET', signal: AbortSignal.timeout(500) });
    if (res.ok) return LOCAL_API_BASE_URL;
  } catch (e) {}

  return PUBLIC_API_BASE_URL;
}

// In-memory mock responses for development/offline testing before backend is live
// ============================================================================
// FEATURE 3: Universal Anti-Redirect & Rogue Popunder Engine (All Websites)
// ============================================================================
const GLOBAL_ALLOWLIST = new Set([
  'google.com', 'accounts.google.com', 'mail.google.com', 'youtube.com',
  'microsoft.com', 'login.microsoftonline.com', 'live.com', 'office.com',
  'apple.com', 'appleid.apple.com', 'icloud.com',
  'amazon.com', 'amazon.in',
  'github.com', 'gitlab.com', 'bitbucket.org',
  'linkedin.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
  'netflix.com', 'spotify.com', 'adobe.com', 'slack.com', 'zoom.us',
  'dropbox.com', 'cloudflare.com', 'paypal.com', 'stripe.com',
  'wikipedia.org', 'reddit.com', 'quora.com', 'medium.com',
  'stackoverflow.com'
]);

const ROGUE_AD_NETWORKS = [
  'adcash', 'propellerads', 'exoclick', 'popcash', 'popads',
  'onclickads', 'hilltopads', 'clickadu', 'trafficjunky', 'adsterra',
  'monetag', 'adkeeper', 'onclickalgo', 'exdynsrv', 'tsyndicate',
  'serving-sys', 'adnxs', 'syndication', 'alwingulla', 'coinhive',
  'popmyads', 'zeroredirect', 'smartlink', 'voluum', 'keitaro',
  'trafficstars', 'admaven', 'juicyads', 'plugrush', 'richpush',
  'rollerads', 'galaksion', 'activepush', 'bidadx', 'clickaine',
  'evadav', 'pushhouse', 'taboola', 'outbrain', 'propeller',
  'popclick', 'redirector', 'ad-delivery', 'clicktracking', 'onclickprediction'
];

const ROGUE_BETTING_KEYWORDS = [
  'parimatch', '1xbet', 'betway', 'bet365', 'melbet', 'mostbet',
  'pin-up', 'pinup', 'vulkan', 'linebet', 'casino', 'gambling',
  'slots', 'poker', 'betting', 'jackpot', 'spinwin', 'roulette'
];

const SCAM_KEYWORDS = [
  'security-alert', 'windows-defender', 'virus-found', 'cleaning-pc',
  'support-alert', 'crypto-airdrop', 'free-gift', 'prize-winner',
  'update-chrome', 'browser-update', 'infected', 'survey-reward',
  'congratulations', 'spin-wheel'
];

const SUSPICIOUS_AFFILIATE_PARAMS = [
  'clickid=', 'click_id=', 'trackid=', 'track_id=', 'aff_c=', 'aff_sub=',
  'aff_id=', 'ref_id=', 'subid=', 'sub_id=', 'zoneid=', 'zone_id=',
  'popunder=', 'target_url=', 'redirect_url=', 'camp_id='
];

const HIGH_RISK_TLDS = [
  '.top', '.click', '.buzz', '.icu', '.monster', '.cfd', '.rest',
  '.gdn', '.skin', '.cam', '.work', '.quest', '.live', '.beauty',
  '.hair', '.fit', '.surf', '.stream', '.party', '.trade', '.racing',
  '.download', '.cf', '.gq', '.tk', '.ml', '.ga'
];

const THREAT_FEED_DOMAINS = [
  'parimatchs-sport.top', 'parimatch.com', 'parimatchs-sp.test',
  'rogue-popunder-demo.test', 'evil-tracker.xyz', 'malicious-phish-bank.com'
];

const sessionBypassedHosts = new Set();
const tabOpenerMap = new Map(); // childTabId -> openerUrl

function getBaseDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function isAllowlistedHost(hostname) {
  if (!hostname) return false;
  const host = hostname.toLowerCase();
  for (const domain of GLOBAL_ALLOWLIST) {
    if (host === domain || host.endsWith('.' + domain)) {
      return true;
    }
  }
  return false;
}

if (typeof chrome !== 'undefined' && chrome.tabs) {
  if (chrome.tabs.onCreated) {
    chrome.tabs.onCreated.addListener(async (tab) => {
      if (tab.openerTabId) {
        try {
          const opener = await chrome.tabs.get(tab.openerTabId);
          if (opener && opener.url) {
            tabOpenerMap.set(tab.id, opener.url);
          }
        } catch (e) {}
      }
    });
  }

  if (chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      tabOpenerMap.delete(tabId);
    });
  }
}

function evaluateUrlForRogueRedirect(url, openerUrl) {
  if (!url) return { isRogue: false };
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    return { isRogue: false };
  }

  const host = urlObj.hostname.toLowerCase();
  const urlLower = url.toLowerCase();
  let openerHost = '';
  if (openerUrl) {
    try {
      openerHost = new URL(openerUrl).hostname.toLowerCase();
    } catch (e) {}
  }

  if (sessionBypassedHosts.has(host)) {
    return { isRogue: false, bypassed: true };
  }

  // Same host internal navigation is never a third-party popunder
  if (host === openerHost) {
    return { isRogue: false };
  }

  // Global verified authentic destinations are never intercepted
  if (isAllowlistedHost(host)) {
    return { isRogue: false };
  }

  const reasons = [];
  let score = 0;
  let category = 'rogue_popunder';

  // 1. Direct Threat Feed
  if (THREAT_FEED_DOMAINS.some(d => host === d || host.endsWith('.' + d))) {
    reasons.push(`Direct threat feed match for known deceptive network ('${host}')`);
    return { isRogue: true, score: 100, category: 'threat_feed_block', reasons, host, openerHost };
  }

  // 2. Known Ad & Popunder Networks
  for (const adNet of ROGUE_AD_NETWORKS) {
    if (host.includes(adNet)) {
      score = Math.max(score, 90);
      category = 'ad_network';
      reasons.push(`Known rogue advertising / popunder network ('${adNet}')`);
      break;
    }
  }

  // 3. Known Betting / Gambling keywords on untrusted domain
  for (const kw of ROGUE_BETTING_KEYWORDS) {
    if (host.includes(kw)) {
      score = Math.max(score, 85);
      category = 'betting_popunder';
      reasons.push(`Deceptive betting / gambling keyword ('${kw}')`);
      break;
    }
  }

  // 4. Known Scam / Scareware keywords
  for (const scamKw of SCAM_KEYWORDS) {
    if (host.includes(scamKw)) {
      score = Math.max(score, 95);
      category = 'scam';
      reasons.push(`Scam / scareware alert pattern detected ('${scamKw}')`);
      break;
    }
  }

  // 5. Deceptive tracking and popunder affiliate tokens
  if (SUSPICIOUS_AFFILIATE_PARAMS.some(p => urlLower.includes(p))) {
    score += 35;
    reasons.push('Deceptive affiliate tracking and popunder tokens detected');
  }

  // 6. High-risk TLD
  for (const tld of HIGH_RISK_TLDS) {
    if (host.endsWith(tld)) {
      score += 30;
      reasons.push(`High-abuse top-level domain (${tld})`);
      break;
    }
  }

  // 7. Cross-origin popunder from media, streaming, piracy, or free content sites
  if (openerHost) {
    const isFreeMediaPortal = ['anime', 'stream', 'movie', 'watch', 'film', 'free', 'torrent', 'crack', 'download', 'serial', 'manga'].some(
      word => openerHost.includes(word)
    );
    if (isFreeMediaPortal) {
      score += 25;
      reasons.push(`Cross-origin popunder spawned by media portal (${openerHost})`);
    } else {
      score += 15;
    }
  }

  const isRogue = score >= 50;

  return {
    isRogue: isRogue,
    score: Math.min(score, 100),
    category,
    reasons,
    host,
    openerHost
  };
}

async function incrementBlockedRedirects(targetUrl, openerUrl) {
  try {
    const data = await chrome.storage.local.get(['phishlens_blocked_count', 'phishlens_blocked_history']);
    const count = (data.phishlens_blocked_count || 0) + 1;
    const history = data.phishlens_blocked_history || [];
    history.unshift({
      timestamp: Date.now(),
      target: targetUrl,
      opener: openerUrl
    });
    if (history.length > 25) history.pop();
    await chrome.storage.local.set({
      phishlens_blocked_count: count,
      phishlens_blocked_history: history
    });
  } catch (e) {}
}

async function redirectToInterstitial(tabId, targetUrl, openerUrl, reasons, category) {
  await incrementBlockedRedirects(targetUrl, openerUrl);
  const interstitialUrl = chrome.runtime.getURL('interstitial.html') +
    '?url=' + encodeURIComponent(targetUrl) +
    '&opener=' + encodeURIComponent(openerUrl || '') +
    '&category=' + encodeURIComponent(category || 'rogue_popunder') +
    '&reasons=' + encodeURIComponent(JSON.stringify(reasons || []));

  try {
    await chrome.tabs.update(tabId, { url: interstitialUrl });
  } catch (err) {
    console.debug('[PhishLens SW] Redirect to interstitial failed:', err);
  }
}

if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const prefix = 'tab_' + details.tabId + '_';
    for (const key of scanRequests.keys()) if (key.startsWith(prefix)) scanRequests.delete(key);
    const entries = await chrome.storage.session.get(null);
    await chrome.storage.session.remove(Object.keys(entries).filter(key => key.startsWith(prefix)));
    updateBadge(details.tabId, 'unknown', null);
    const url = details.url;
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('data:')) {
      return;
    }

    try {
      const settings = await chrome.storage.local.get(['phishlens_redirect_shield', 'phishlens_paused']);
      if (settings && (settings.phishlens_paused === true || settings.phishlens_redirect_shield === false)) {
        return;
      }
    } catch (e) {}

    const openerUrl = tabOpenerMap.get(details.tabId) || '';
    const evalResult = evaluateUrlForRogueRedirect(url, openerUrl);

    if (evalResult.isRogue) {
      console.log('[PhishLens SW] Intercepted rogue redirect navigation:', url, evalResult);
      await redirectToInterstitial(details.tabId, url, openerUrl, evalResult.reasons, evalResult.category);
      return;
    }

    // Backend fallback verification if query has suspicious tokens or opener is external
    if (evalResult.score >= 20 || (openerUrl && url.includes('?'))) {
      try {
        const baseUrl = await getApiBaseUrl();
        const checkUrl = `${baseUrl}/check-redirect?url=${encodeURIComponent(url)}&opener=${encodeURIComponent(openerUrl)}`;
        const res = await fetch(checkUrl, { signal: AbortSignal.timeout(600) });
        if (res.ok) {
          const data = await res.json();
          if (data && data.is_rogue && data.blocked) {
            console.log('[PhishLens SW] Backend confirmed rogue redirect:', url, data);
            await redirectToInterstitial(details.tabId, url, openerUrl, data.reasons, data.category);
          }
        }
      } catch (e) {}
    }
  });
}

function unavailableScan(payload) {
  return { url: payload.url, score: null, verdict: 'unknown', signals: [],
    error: 'Analysis unavailable. Check the backend connection and retry.' };
}

function fallbackExplanation(scan) {
  return {
    verdict: scan.verdict === 'danger' ? 'phishing' : scan.verdict,
    reasons: (scan.signals || []).map(s => s.detail).filter(Boolean).slice(0, 3),
    advice: 'Verify the website independently before entering credentials.'
  };
}

async function scanCacheKey(payload) {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}

const scanRequests = new Map();
function frameKey(tabId, frameId) { return 'tab_' + tabId + '_' + frameId; }

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

async function setTabScan(tabId, scanData, explanation = null, frameId = 0, pageUrl = scanData.url) {
  try {
    const key = frameKey(tabId, frameId);
    await chrome.storage.session.set({
      [key]: {
        tabId: tabId,
        frameId,
        pageUrl,
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

async function refreshTabBadge(tabId, pageUrl) {
  const entries = await chrome.storage.session.get(null);
  const scans = Object.entries(entries)
    .filter(([key, value]) => key.startsWith('tab_' + tabId + '_') && value.pageUrl === pageUrl)
    .map(([, value]) => value.data);
  const priority = scan => scan.verdict === 'unknown' ? 29 : scan.score;
  scans.sort((a, b) => priority(b) - priority(a));
  if (scans[0]) updateBadge(tabId, scans[0].verdict, scans[0].score);
}

function updateBadge(tabId, verdict, score) {
  if (!chrome.action) return;

  if (verdict === 'unknown') {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });
  } else if (verdict === 'danger') {
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
  const timer = setTimeout(() => controller.abort(), 3500);

  try {
    const baseUrl = await getApiBaseUrl();
    const res = await fetch(`${baseUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (res.ok) {
      const data = await res.json();
      if (data && typeof data.scan_id === 'string' && Number.isFinite(data.score)
          && data.score >= 0 && data.score <= 100 && Array.isArray(data.signals)
          && data.verdict === (data.score >= 60 ? 'danger' : data.score >= 30 ? 'suspicious' : 'safe')) {
        return data;
      }
    }
  } catch (err) {
    clearTimeout(timer);
    console.debug('[PhishLens SW] /analyze fetch failed:', err.message);
  }

  // Fallback to contract mock if backend is down or not started yet
  return unavailableScan(payload);
}

async function fetchExplanation(scanId, cacheKey, tabId, scanResult, frameId, pageUrl, token) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4500);

  let explanation = null;

  try {
    const baseUrl = await getApiBaseUrl();
    const res = await fetch(`${baseUrl}/explain/${encodeURIComponent(scanId)}`, {
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
    explanation = fallbackExplanation(scanResult);
  }

  if (explanation) {
    // Update cache
    await setCachedScan(cacheKey, scanResult, explanation);
    if (tabId != null && scanRequests.get(frameKey(tabId, frameId)) === token) {
      await setTabScan(tabId, scanResult, explanation, frameId, pageUrl);
      // Forward to content script
      try {
        await chrome.tabs.sendMessage(tabId, {
          action: 'EXPLAIN_RESULT', scan_id: scanId, explanation
        }, { frameId });
      } catch (e) {
        console.debug('[PhishLens SW] Forward explanation failed:', e);
      }
    }
  }
}

// Runtime message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.action !== 'string') return false;
  const tabId = sender.tab ? sender.tab.id : null;

  if (message.action === 'ANALYZE_PAGE') {
    const payload = message.payload;
    if (!payload || !payload.url || tabId == null) {
      sendResponse({ success: false, error: 'Empty payload or missing tab' });
      return false;
    }
    const frameId = sender.frameId || 0;
    const pageUrl = sender.tab.url;
    const key = frameKey(tabId, frameId);
    const token = Symbol();
    scanRequests.set(key, token);
    (async () => {
      const cacheKey = await scanCacheKey(payload);
      const cached = message.force ? null : await getCachedScan(cacheKey);
      const scanResult = cached ? cached.data : await fetchAnalyze(payload);
      scanResult.url = payload.url;
      if (scanRequests.get(key) !== token) {
        sendResponse({ success: false, error: 'Superseded scan' });
        return;
      }
      const explanation = cached ? cached.explanation : null;
      await setTabScan(tabId, scanResult, explanation, frameId, pageUrl);
      await refreshTabBadge(tabId, pageUrl);
      if (!cached && scanResult.verdict !== 'unknown') {
        await setCachedScan(cacheKey, scanResult);
      }
      sendResponse({ success: true, data: scanResult, explanation });
      if (!explanation && scanResult.score >= 30 && scanResult.scan_id) {
        await fetchExplanation(scanResult.scan_id, cacheKey, tabId, scanResult, frameId, pageUrl, token);
      }
    })().catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.action === 'GET_TAB_SCAN') {
    (async () => {
      const targetTabId = message.tabId ?? tabId;
      const entries = await chrome.storage.session.get(null);
      const scans = Object.entries(entries)
        .filter(([key, value]) => key.startsWith('tab_' + targetTabId + '_')
          && value.pageUrl === message.url)
        .map(([, value]) => value);
      // A safe iframe must not hide a dangerous parent (or vice versa).
      scans.sort((a, b) => (b.data.score ?? 29) - (a.data.score ?? 29));
      sendResponse({ scan: scans[0] || null });
    })().catch(err => sendResponse({ scan: null, error: err.message }));
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

  // ==========================================================================
  // FEATURE 3 Action Handlers
  // ==========================================================================
  if (message.action === 'CLOSE_CURRENT_TAB') {
    if (tabId) {
      chrome.tabs.remove(tabId);
    }
    sendResponse({ success: true });
    return true;
  }

  if (message.action === 'RETURN_TO_SOURCE') {
    (async () => {
      const openerUrl = message.openerUrl;
      if (openerUrl) {
        try {
          const openerDomain = new URL(openerUrl).hostname;
          const tabs = await chrome.tabs.query({});
          const matchTab = tabs.find(t => {
            try { return t.id !== tabId && new URL(t.url).origin === new URL(openerUrl).origin; }
            catch (_) { return false; }
          });
          if (matchTab) {
            await chrome.tabs.update(matchTab.id, { active: true });
          }
        } catch (e) {}
      }
      if (tabId) {
        chrome.tabs.remove(tabId);
      }
      sendResponse({ success: true });
    })();
    return true;
  }

  if (message.action === 'ALLOW_AND_PROCEED') {
    const targetUrl = message.url;
    if (targetUrl) {
      try {
        const host = new URL(targetUrl).hostname.toLowerCase();
        sessionBypassedHosts.add(host);
      } catch (e) {}
    }
    sendResponse({ success: true });
    return true;
  }

  if (message.action === 'REPORT_ROUGE_REDIRECT') {
    incrementBlockedRedirects(message.url, message.opener);
    sendResponse({ success: true });
    return true;
  }

  if (message.action === 'GET_BLOCKED_REDIRECTS_STATS') {
    (async () => {
      const data = await chrome.storage.local.get(['phishlens_blocked_count', 'phishlens_blocked_history', 'phishlens_redirect_shield']);
      sendResponse({
        count: data.phishlens_blocked_count || 0,
        history: data.phishlens_blocked_history || [],
        shieldActive: data.phishlens_redirect_shield !== false
      });
    })();
    return true;
  }

  if (message.action === 'TOGGLE_REDIRECT_SHIELD') {
    (async () => {
      const current = await chrome.storage.local.get(['phishlens_redirect_shield']);
      const newState = current.phishlens_redirect_shield === false ? true : false;
      await chrome.storage.local.set({ phishlens_redirect_shield: newState });
      sendResponse({ shieldActive: newState });
    })();
    return true;
  }

  // ==========================================================================
  // Community Reporting Handlers (Feature 1)
  // ==========================================================================
  if (message.action === 'REPORT_PHISHING') {
    (async () => {
      const targetUrl = message.url;
      if (!targetUrl) {
        sendResponse({ success: false, error: 'Missing target URL' });
        return;
      }
      try {
        const baseUrl = await getApiBaseUrl();
        const res = await fetch(`${baseUrl}/report`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
          signal: AbortSignal.timeout(4000)
        });
        if (!res.ok) throw new Error('Report failed: HTTP ' + res.status);
        const data = await res.json();
        if (!Number.isInteger(data.reports_count) || data.reports_count < 0) throw new Error('Invalid report response');
        // Clear stale report counts; the next scan must consult the backend.
        const entries = await chrome.storage.session.get(null);
        await chrome.storage.session.remove(Object.keys(entries).filter(key => key.startsWith('cache_')));
        sendResponse({ success: true, data: data });
      } catch (err) {
        console.warn('[PhishLens SW] Community report submission failed:', err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.action === 'GET_REPORTS_COUNT') {
    (async () => {
      const targetUrl = message.url;
      if (!targetUrl) {
        sendResponse({ success: false, reports_count: 0 });
        return;
      }
      try {
        const baseUrl = await getApiBaseUrl();
        const res = await fetch(`${baseUrl}/report?url=${encodeURIComponent(targetUrl)}`);
        const data = await res.json();
        sendResponse({ success: true, reports_count: data.reports_count || 0 });
      } catch (err) {
        sendResponse({ success: false, reports_count: 0 });
      }
    })();
    return true;
  }

  return false;
});

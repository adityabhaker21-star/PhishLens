/**
 * PhishLens - Universal Main-World Popunder & Rogue Redirect Shield (shield_main.js)
 * Executes in the MAIN page execution context at document_start.
 * Intercepts rogue window.open popunders, programmatic anchor clicks,
 * transparent clickjack overlays, and tab-under hijacks across ALL websites.
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__phishLensMainShieldInstalled) return;
  window.__phishLensMainShieldInstalled = true;

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

  const SUSPICIOUS_PARAMS = [
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

  function getBaseDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  function isAllowlisted(hostname) {
    if (!hostname) return false;
    const host = hostname.toLowerCase();
    for (const domain of GLOBAL_ALLOWLIST) {
      if (host === domain || host.endsWith('.' + domain)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Universal Evaluator: Decides if an outgoing target URL is a rogue popunder or ad redirect.
   */
  function isRogueDestination(url) {
    if (!url || typeof url !== 'string') return false;
    const trimmed = url.trim();
    if (trimmed === '' || trimmed === 'about:blank' || trimmed.startsWith('javascript:')) {
      return false;
    }

    try {
      const parsed = new URL(trimmed, window.location.href);
      const host = parsed.hostname.toLowerCase();
      const currentHost = window.location.hostname.toLowerCase();

      // Same host or same base domain is legitimate internal navigation
      if (host === currentHost) {
        return false;
      }

      // Recognized safe global portals
      if (isAllowlisted(host)) {
        return false;
      }

      const urlLower = parsed.href.toLowerCase();

      // 1. Known Ad / Popunder Network match
      if (ROGUE_AD_NETWORKS.some(ad => host.includes(ad))) {
        return true;
      }

      // 2. Known Betting / Gambling keywords on untrusted third-party host
      if (ROGUE_BETTING_KEYWORDS.some(kw => host.includes(kw))) {
        return true;
      }

      // 3. Scam / Scareware patterns
      if (SCAM_KEYWORDS.some(kw => host.includes(kw))) {
        return true;
      }

      // A tracking parameter or TLD alone is not proof of a rogue destination.
      // Require both instead of blocking legitimate affiliate links and websites.
      if (SUSPICIOUS_PARAMS.some(p => urlLower.includes(p)) &&
          HIGH_RISK_TLDS.some(tld => host.endsWith(tld))) return true;

      return false;
    } catch (e) {
      return false;
    }
  }

  function notifyBlocked(targetUrl, reason) {
    try {
      window.postMessage({
        type: 'PHISHLENS_POPUNDER_BLOCKED',
        url: targetUrl,
        reason: reason || 'Rogue popunder blocked'
      }, '*');
    } catch (e) {}
  }

  // ==========================================================================
  // 1. Monkeypatch window.open in the MAIN World
  // ==========================================================================
  const _realWindowOpen = window.open;

  window.open = function (url, target, features) {
    if (url && typeof url === 'string') {
      if (isRogueDestination(url)) {
        console.warn('[PhishLens Shield] Intercepted rogue window.open popunder call to:', url);
        notifyBlocked(url, 'Rogue popunder window.open call intercepted');

        // Return a mock Window object so the caller script does not throw a JS error
        return {
          closed: false,
          focus: function () {},
          blur: function () {},
          close: function () {},
          document: { write: function () {} },
          location: {
            set href(val) {
              if (isRogueDestination(val)) {
                notifyBlocked(val, 'Tab-under location assignment blocked');
              }
            },
            get href() { return ''; },
            replace: function () {},
            assign: function () {}
          }
        };
      }
    }

    // Call real window.open for safe / legitimate URLs
    return _realWindowOpen.apply(this, arguments);
  };

  // ==========================================================================
  // 2. Monkeypatch HTMLAnchorElement.prototype.click
  // ==========================================================================
  const _realAnchorClick = HTMLAnchorElement.prototype.click;

  HTMLAnchorElement.prototype.click = function () {
    const href = this.href;
    if (href && isRogueDestination(href)) {
      console.warn('[PhishLens Shield] Intercepted programmatic click on rogue anchor:', href);
      notifyBlocked(href, 'Programmatic click on rogue link blocked');
      return;
    }
    return _realAnchorClick.apply(this, arguments);
  };

  // ==========================================================================
  // 3. Neutralize Invisible Full-Screen Clickjack Overlays in the DOM
  // ==========================================================================
  function scanAndNeutralizeOverlays() {
    try {
      const vw = window.innerWidth || document.documentElement.clientWidth;
      const vh = window.innerHeight || document.documentElement.clientHeight;
      if (!vw || !vh) return;

      const candidates = document.querySelectorAll('a, div, span, section, iframe');
      for (let i = 0; i < candidates.length; i++) {
        const el = candidates[i];
        if (el.id && el.id.startsWith('phishlens-')) continue;

        const rect = el.getBoundingClientRect();
        // Covers >= 70% of viewport
        if (rect.width >= vw * 0.70 && rect.height >= vh * 0.70) {
          const style = window.getComputedStyle(el);
          const isFixedOrAbs = style.position === 'fixed' || style.position === 'absolute';
          const isTransparent = style.opacity === '0' ||
            style.opacity === '0.001' ||
            style.backgroundColor === 'transparent' ||
            style.backgroundColor === 'rgba(0, 0, 0, 0)';
          const highZ = parseInt(style.zIndex, 10) > 100;

          if (isFixedOrAbs && isTransparent && highZ) {
            // If it's an anchor or has click handler or transparent overlay
            if (el.tagName === 'A' && isRogueDestination(el.href)) {
              console.warn('[PhishLens Shield] Neutralized transparent full-screen link overlay:', el.href);
              el.style.pointerEvents = 'none';
              el.remove();
              notifyBlocked(el.href, 'Transparent clickjack link overlay neutralized');
            }
          }
        }
      }
    } catch (e) {}
  }

  // Intercept top-level click capture on document
  document.addEventListener(
    'click',
    function (e) {
      const anchor = e.target ? e.target.closest('a') : null;
      if (anchor && anchor.href && isRogueDestination(anchor.href)) {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        console.warn('[PhishLens Shield] Click on rogue destination blocked:', anchor.href);
        notifyBlocked(anchor.href, 'Rogue click navigation blocked');
      }
    },
    true
  );

  // Run overlay scan on load and when DOM changes
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanAndNeutralizeOverlays);
  } else {
    scanAndNeutralizeOverlays();
  }

  // Periodic lightweight overlay scan
  setInterval(scanAndNeutralizeOverlays, 2000);

  console.log('[PhishLens] Universal Main-World Anti-Redirect Shield active on', window.location.hostname);
})();

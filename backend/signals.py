"""
PhishLens Detection Signals Engine
Implements rule-based heuristic and threat-intel signals for phishing detection.
"""

import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse, urljoin
import tldextract

# Use the bundled Public Suffix List; scoring must not download it at runtime.
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                       include_psl_private_domains=True)

def _domain_label(host: str) -> str:
    extracted = _DOMAIN_EXTRACTOR(host)
    if extracted.suffix:
        return extracted.domain
    parts = host.split('.')
    return parts[-2] if len(parts) > 1 else host

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

# Try importing rapidfuzz, fallback to pure-Python implementation
try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    HAS_RAPIDFUZZ = False

# Try importing httpx for async/sync RDAP lookups
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# Paths to local configuration and threat feeds
BASE_DIR = Path(__file__).parent
BRANDS_PATH = BASE_DIR / "brands.json"
THREAT_FEED_PATH = BASE_DIR / "threat_feed.json"

def _load_brands_list() -> List[Dict[str, Any]]:
    """Load brand list supporting both JSON array format and {'brands': [...]} object format."""
    if not BRANDS_PATH.exists():
        return []
    try:
        with open(BRANDS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return data.get("brands", [])
    except Exception:
        pass
    return []

# Known mock newly registered domains for offline/hackathon demo reliability
MOCK_NEW_DOMAINS = {
    "novabank-kyc-verify.test": 3,   # registered 3 days ago (demo fake)
    "borderline.test": 4,            # registered 4 days ago (demo borderline)
    "novabank-kyc-verify.xyz": 3,   # registered 3 days ago
    "secure-verify-update.top": 2,  # registered 2 days ago
    "paypal-login-alert.online": 5, # registered 5 days ago
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate exact Levenshtein edit distance between two strings."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )
    return dp[m][n]


def _levenshtein_ratio(s1: str, s2: str) -> float:
    """Calculate normalized similarity ratio between two strings (0.0 to 1.0)."""
    if HAS_RAPIDFUZZ:
        return fuzz.ratio(s1, s2) / 100.0

    m, n = len(s1), len(s2)
    if m == 0 or n == 0:
        return 0.0

    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max(m, n))


def _normalize_leetspeak(text: str) -> str:
    """Normalize common phishing character substitutions (e.g. 0->o, 1->l, @->a)."""
    substitutions = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '@': 'a',
        '5': 's',
        'vv': 'w',
        'rn': 'm',
    }
    result = text.lower()
    for char, replacement in substitutions.items():
        result = result.replace(char, replacement)
    return result


def _extract_hostname(url: str) -> str:
    """Extract clean lowercase hostname from URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.path.split("/")[0]
        return host.lower().rstrip('.')
    except Exception:
        return ""


# ============================================================================
# SIGNAL 1: Threat Feed Hit (100 Points)
# ============================================================================
def signal_threat_feed(url: str) -> Optional[Dict[str, Any]]:
    """
    Checks if the URL or host matches known malicious entries in local threat feed.
    Gives immediate 100 points (Danger).
    """
    if not THREAT_FEED_PATH.exists():
        return None

    try:
        with open(THREAT_FEED_PATH, "r", encoding="utf-8") as f:
            feed_data = json.load(f)

        host = _extract_hostname(url)
        normalized_url = url.strip().lower()

        known_urls = [u.strip().lower() for u in feed_data.get("urls", [])]
        known_domains = [d.strip().lower() for d in feed_data.get("domains", [])]

        if normalized_url in known_urls:
            return {
                "id": "threat_feed_hit",
                "points": 100,
                "detail": f"Exact URL '{url}' found in active threat intelligence blocklist"
            }

        for domain in known_domains:
            if host == domain or host.endswith("." + domain):
                return {
                    "id": "threat_feed_hit",
                    "points": 100,
                    "detail": f"Domain '{host}' matches known phishing infrastructure blocklist"
                }

    except Exception:
        pass

    return None


# ============================================================================
# SIGNAL 2: Brand Mismatch (30 Points)
# ============================================================================
def signal_brand_mismatch(url: str, text: str) -> Optional[Dict[str, Any]]:
    """
    Detects if the page mentions a known brand (e.g. Nova Bank)
    but is hosted on a domain that does NOT belong to that brand.
    """
    brands = _load_brands_list()
    if not brands:
        return None

    try:
        host = _extract_hostname(url)
        text_lower = text.lower()

        for brand in brands:
            brand_domains = [d.lower() for d in brand.get("domains", [])]
            keywords = [k.lower() for k in brand.get("keywords", [])]

            # Check if text claims to be this brand
            mentioned = any(kw in text_lower for kw in keywords)

            # Check if domain is an official domain
            official = any(host == domain or host.endswith("." + domain) for domain in brand_domains)

            if mentioned and not official:
                return {
                    "id": "brand_mismatch",
                    "points": 30,
                    "detail": f"Page claims to represent {brand['name']} but is hosted on unauthorized domain '{host}'"
                }

    except Exception:
        pass

    return None


# ============================================================================
# SIGNAL 3: Lookalike Domain / Typosquatting (25 Points)
# ============================================================================
def signal_lookalike_domain(url: str) -> Optional[Dict[str, Any]]:
    """
    Detects lookalike/typosquatted domains (e.g. novabnak.test, paypa1.com, g00gle.com)
    targeting known brand domains using Levenshtein distance and character normalization.
    """
    brands = _load_brands_list()
    if not brands:
        return None

    try:
        host = _extract_hostname(url)
        if not host:
            return None

        # Extract primary second-level domain name part
        host_parts = host.split(".")
        candidate_name = _domain_label(host)
        if any(host == d or host.endswith("." + d)
               for brand in brands for d in brand.get("domains", [])):
            return None
        normalized_candidate = _normalize_leetspeak(candidate_name)

        # Check 0: Punycode / IDN homograph attack
        if "xn--" in host:
            return {
                "id": "lookalike_domain",
                "points": 25,
                "detail": f"Domain '{host}' uses Punycode (xn--) internationalized homograph encoding"
            }

        for brand in brands:
            for official_domain in brand.get("domains", []):
                # If exact match or subdomain of official, ignore
                if host == official_domain or host.endswith("." + official_domain):
                    continue

                official_parts = official_domain.split(".")
                official_name = _domain_label(official_domain)

                # Check 1: Leetspeak normalized match (e.g. g00gle -> google)
                if normalized_candidate == official_name:
                    return {
                        "id": "lookalike_domain",
                        "points": 25,
                        "detail": f"Domain '{host}' uses deceptive character substitution targeting {brand['name']} ({official_domain})"
                    }

                # Check 2: High edit similarity / typosquatting (edit distance <= 2 per spec)
                dist = _levenshtein_distance(candidate_name, official_name)
                similarity = _levenshtein_ratio(candidate_name, official_name)
                if (dist <= (1 if len(official_name) < 5 else 2) and similarity >= 0.60
                    or similarity >= 0.80) and candidate_name != official_name:
                    return {
                        "id": "lookalike_domain",
                        "points": 25,
                        "detail": f"Domain '{host}' is a close visual lookalike to official {brand['name']} domain '{official_domain}'"
                    }

                # Check 3: Brand name embedded with hyphens/prefixes (e.g. novabank-verify.xyz)
                if official_name in candidate_name and candidate_name != official_name:
                    return {
                        "id": "lookalike_domain",
                        "points": 25,
                        "detail": f"Domain '{host}' deceptive name embeds official brand '{brand['name']}'"
                    }

    except Exception:
        pass

    return None


# ============================================================================
# SIGNAL 4: Form Action Mismatch (20 Points)
# ============================================================================
def signal_form_action_mismatch(url: str, forms: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """
    Detects when a login or credential form submits data to a foreign external domain,
    an insecure HTTP destination on an HTTPS page, or an unverified endpoint.
    """
    if not forms or not isinstance(forms, list):
        return None

    page_host = _extract_hostname(url)
    page_scheme = urlparse(url).scheme

    for form in forms:
        if form.get("has_password") is False:
            continue
        action = form.get("action", "").strip()
        if not action:
            continue

        # Relative paths like '/login' or 'auth.php' submit to same origin (Safe)
        if action.startswith("/") and not action.startswith("//"):
            continue

        parsed_action = urlparse(urljoin(url, action))
        action_host = parsed_action.hostname or ""
        action_scheme = parsed_action.scheme

        # Case A: HTTPS page submitting credentials over insecure plain HTTP
        if page_scheme == "https" and action_scheme == "http":
            return {
                "id": "form_action_mismatch",
                "points": 20,
                "detail": f"Form on secure page submits sensitive data over insecure HTTP to '{action}'"
            }

        # Case B: Cross-domain submission to a different foreign domain
        if action_host and action_host != page_host:
            # Check if it's not a direct subdomain of the page host
            if not action_host.endswith("." + page_host) and not page_host.endswith("." + action_host):
                return {
                    "id": "form_action_mismatch",
                    "points": 20,
                    "detail": f"Form submits credentials to foreign external destination '{action_host}'"
                }

    return None


# ============================================================================
# SIGNAL 5: Insecure HTTP or Raw IP (15 Points)
# ============================================================================
def signal_insecure_or_ip(url: str) -> Optional[Dict[str, Any]]:
    """Detects HTTP instead of HTTPS or raw IP addresses."""
    parsed = urlparse(url)
    host = parsed.hostname or ""

    points = 0
    reasons = []

    if parsed.scheme == "http":
        points += 15
        reasons.append("Website uses insecure HTTP instead of HTTPS")

    try:
        ipaddress.ip_address(host)
        points += 15
        reasons.append("Website uses a raw IP address instead of a domain name")
    except ValueError:
        pass

    if points == 0:
        return None

    return {
        "id": "insecure_or_ip",
        "points": min(points, 15),
        "detail": ", ".join(reasons)
    }


# ============================================================================
# SIGNAL 6: New Domain (15 Points)
# ============================================================================
def signal_new_domain(url: str) -> Optional[Dict[str, Any]]:
    """
    Detects if the domain was registered recently (< 30 days old).
    Uses mock dictionary for hackathon demo certainty and RDAP with strict short timeout.
    """
    host = _extract_hostname(url)
    if not host:
        return None

    # 1. Check hackathon mock registry first (ensures deterministic demo)
    if host in MOCK_NEW_DOMAINS:
        age_days = MOCK_NEW_DOMAINS[host]
        return {
            "id": "new_domain",
            "points": 15,
            "detail": f"Domain '{host}' was registered only {age_days} days ago (newly created domain)"
        }

    # Test/local environments cannot be looked up in RDAP
    if host.endswith(".test") or host.endswith(".local") or host == "localhost":
        return None

    # 2. Live RDAP check with 1.2s timeout (fails open quickly)
    if HAS_HTTPX:
        try:
            # Query rdap.org
            rdap_url = f"https://rdap.org/domain/{host}"
            with httpx.Client(timeout=1.2, follow_redirects=True) as client:
                resp = client.get(rdap_url)
                if resp.status_code == 200:
                    rdap_data = resp.json()
                    events = rdap_data.get("events", [])
                    for ev in events:
                        if ev.get("eventAction") == "registration":
                            reg_date_str = ev.get("eventDate", "")
                            # Parse ISO timestamp
                            reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                            age = (datetime.now(timezone.utc) - reg_date).days
                            if age < 30:
                                return {
                                    "id": "new_domain",
                                    "points": 15,
                                    "detail": f"Domain '{host}' was registered {age} days ago (< 30 days)"
                                }
        except Exception:
            # Fail open gracefully if no internet or timeout
            pass

    return None


# ============================================================================
# SIGNAL 7: Urgency Language (10 Points)
# ============================================================================
def signal_urgency_language(text: str) -> Optional[Dict[str, Any]]:
    """Detects social engineering and urgent pressure language."""
    keywords = [
        "kyc",
        "account blocked",
        "account suspended",
        "verify within",
        "expires in",
        "immediately",
        "urgent",
        "verify now",
        "suspended",
        "limited access",
        "unauthorized activity",
        "action required"
    ]

    text_lower = text.lower()
    found = [word for word in keywords if word in text_lower]

    if not found:
        return None

    return {
        "id": "urgency_language",
        "points": 10,
        "detail": f"Urgency language detected: {', '.join(found)}"
    }


# ============================================================================
# SIGNAL 8: Suspicious URL Shape (10 Points)
# ============================================================================
def signal_url_shape(url: str) -> Optional[Dict[str, Any]]:
    """Detects structural anomalies in the URL (length, @, excessive subdomains, cheap TLDs)."""
    points = 0
    reasons = []

    if len(url) > 75:
        points += 5
        reasons.append("URL length exceeds 75 characters")

    if "@" in url:
        points += 10
        reasons.append("URL contains '@' credential confusion symbol")

    try:
        host = _extract_hostname(url)
        parts = host.split(".")

        if len(parts) >= 4:
            points += 5
            reasons.append(f"Excessive subdomains ({len(parts)} levels)")

        cheap_tlds = [".xyz", ".top", ".click", ".online", ".site", ".shop", ".work", ".buzz"]
        if any(host.endswith(tld) for tld in cheap_tlds):
            points += 5
            reasons.append("URL uses a low-reputation / cheap TLD")

    except Exception:
        pass

    if points == 0:
        return None

    return {
        "id": "url_shape",
        "points": min(points, 10),
        "detail": ", ".join(reasons)
    }


# ============================================================================
# FEATURE 3: Anti-Redirect & Rogue Popunder Detection
# ============================================================================
ROGUE_BETTING_KEYWORDS = [
    "parimatch", "1xbet", "betway", "bet365", "melbet", "mostbet",
    "pin-up", "pinup", "vulkan", "linebet", "casino", "gambling",
    "slots", "poker", "betting", "jackpot", "spinwin", "roulette"
]

ROGUE_AD_NETWORKS = [
    "adcash", "propellerads", "exoclick", "popcash", "popads",
    "onclickads", "hilltopads", "clickadu", "trafficjunky", "adsterra",
    "monetag", "adkeeper", "onclickalgo", "exdynsrv", "tsyndicate",
    "serving-sys", "adnxs", "syndication", "alwingulla", "coinhive",
    "popmyads", "zeroredirect", "smartlink", "voluum", "keitaro",
    "trafficstars", "admaven", "juicyads", "plugrush", "richpush",
    "rollerads", "galaksion", "activepush", "bidadx", "clickaine",
    "evadav", "pushhouse", "taboola", "outbrain", "propeller",
    "popclick", "redirector", "ad-delivery", "clicktracking", "onclickprediction"
]

HIGH_RISK_TLDS = [
    ".top", ".click", ".buzz", ".icu", ".monster", ".cfd", ".rest",
    ".gdn", ".skin", ".cam", ".work", ".quest", ".live", ".beauty",
    ".hair", ".fit", ".surf", ".stream", ".party", ".trade", ".racing",
    ".download", ".cf", ".gq", ".tk", ".ml", ".ga"
]

SCAM_ALERT_KEYWORDS = [
    "security-alert", "windows-defender", "virus-found", "cleaning-pc",
    "support-alert", "crypto-airdrop", "free-gift", "prize-winner",
    "update-chrome", "browser-update", "infected", "survey-reward",
    "congratulations", "spin-wheel"
]

SUSPICIOUS_PARAMS = [
    "clickid=", "click_id=", "trackid=", "track_id=", "aff_c=", "aff_sub=",
    "aff_id=", "ref_id=", "subid=", "sub_id=", "zoneid=", "zone_id=",
    "popunder=", "target_url=", "redirect_url=", "camp_id="
]


def evaluate_redirect_safety(url: str, opener: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates outgoing navigations, popunders, and rogue redirects across ALL websites.
    Detects unauthorized ad networks, deceptive betting popunders, tracking rotators,
    and scam redirects before they harm the user.
    """
    reasons = []
    risk_score = 0
    category = "clean"
    host = _extract_hostname(url).lower()
    opener_host = _extract_hostname(opener).lower() if opener else ""
    url_lower = url.lower()

    # 1. Exact match in active threat intelligence feed
    tf_hit = signal_threat_feed(url)
    if tf_hit:
        reasons.append(f"Confirmed Malicious: {tf_hit['detail']}")
        return {
            "is_rogue": True,
            "risk_score": 100,
            "category": "threat_feed_block",
            "reasons": reasons,
            "blocked": True,
            "host": host,
            "opener_host": opener_host
        }

    # 2. Check for Known Popunder & Rogue Ad Networks
    for ad_net in ROGUE_AD_NETWORKS:
        if ad_net in host:
            risk_score = max(risk_score, 90)
            category = "ad_network"
            reasons.append(f"Known rogue popunder / advertising gateway ('{ad_net}')")
            break

    # 3. Check for Rogue Betting / Gambling Popunders
    for kw in ROGUE_BETTING_KEYWORDS:
        if kw in host:
            risk_score = max(risk_score, 85)
            category = "betting_popunder"
            reasons.append(f"Rogue betting/gambling network signature detected ('{kw}')")
            break

    # 4. Check for Fake Security Alert / Scam Patterns
    for scam_kw in SCAM_ALERT_KEYWORDS:
        if scam_kw in host:
            risk_score = max(risk_score, 95)
            category = "scam"
            reasons.append(f"Deceptive scareware / scam alert keyword detected ('{scam_kw}')")
            break

    # 5. Check for Tracking / Affiliate popunder payload parameters
    if any(param in url_lower for param in SUSPICIOUS_PARAMS):
        risk_score += 35
        reasons.append("Contains deceptive affiliate click-hijack tracking parameters")

    # 6. Check High-Risk TLDs combined with popunder behavior
    for tld in HIGH_RISK_TLDS:
        if host.endswith(tld):
            risk_score += 30
            reasons.append(f"High-abuse top-level domain frequently used for rogue popunders ('{tld}')")
            break

    # 7. Context: Cross-origin opener
    if opener_host and opener_host != host:
        if any(stream_word in opener_host for stream_word in ["anime", "stream", "movie", "watch", "film", "free", "torrent", "crack", "download"]):
            risk_score += 25
            reasons.append(f"Cross-origin popunder spawned by media portal '{opener_host}'")
        else:
            risk_score += 15

    is_rogue = risk_score >= 50

    return {
        "is_rogue": is_rogue,
        "risk_score": min(risk_score, 100),
        "category": category if is_rogue else "clean",
        "reasons": reasons,
        "blocked": is_rogue,
        "host": host,
        "opener_host": opener_host
    }


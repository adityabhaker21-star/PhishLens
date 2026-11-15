import sys
import json
import urllib.request
import urllib.error
import urllib.parse

API_URL = "http://127.0.0.1:8000/analyze"

LEGITIMATE_TEST_SET = [
    {"url": "https://accounts.google.com/signin", "title": "Sign in - Google Accounts"},
    {"url": "https://login.microsoftonline.com/", "title": "Sign in to your account"},
    {"url": "https://github.com/login", "title": "Sign in to GitHub"},
    {"url": "https://www.amazon.com/ap/signin", "title": "Amazon Sign-In"},
    {"url": "https://www.amazon.in/ap/signin", "title": "Amazon Sign-In"},
    {"url": "https://appleid.apple.com/sign-in", "title": "Sign In - Apple"},
    {"url": "https://www.linkedin.com/login", "title": "LinkedIn Login"},
    {"url": "https://netbanking.hdfcbank.com/netbanking/", "title": "Welcome to HDFC Bank NetBanking"},
    {"url": "https://infinity.icicibank.com/corp/AuthenticationController", "title": "ICICI Bank Internet Banking"},
    {"url": "https://retail.onlinesbi.sbi/retail/login.htm", "title": "State Bank of India - Personal Banking"},
    {"url": "https://omni.axisbank.co.in/axisretailbanking/", "title": "Axis Bank Internet Banking Login"},
    {"url": "https://twitter.com/i/flow/login", "title": "Log in to X / Twitter"},
    {"url": "https://www.netflix.com/login", "title": "Netflix - Sign In"},
    {"url": "https://www.spotify.com/in-en/login/", "title": "Login - Spotify"},
    {"url": "https://auth.services.adobe.com/en_US/deeplink.html", "title": "Adobe ID Login"},
    {"url": "https://slack.com/signin", "title": "Sign in to Slack"},
    {"url": "https://www.dropbox.com/login", "title": "Login - Dropbox"},
    {"url": "https://id.atlassian.com/login", "title": "Log in to Atlassian"},
    {"url": "https://www.paypal.com/signin", "title": "Log in to your PayPal account"},
    {"url": "https://zerodha.com/kite/login", "title": "Kite - Zerodha's fast and elegant flagship trading platform"}
]

PHISHING_TEST_SET = [
    {"url": "http://novabank-kyc-verify.test:8080/login", "title": "Nova Bank Net Banking Login"},
    {"url": "http://secure-sbi-kyc-update-alert.xyz/portal", "title": "State Bank of India Online KYC Update"},
    {"url": "http://hdfc-netbanking-secure-verification.top/auth", "title": "HDFC Netbanking Urgent Verification"},
    {"url": "http://icici-bank-rewards-claim.xyz/login.php", "title": "ICICI Bank Reward Points Portal"},
    {"url": "http://paytm-kyc-suspended-verify.xyz/wallet", "title": "Paytm Wallet KYC Verification"},
    {"url": "http://accounts.google.com.security-verify-alert.top/login", "title": "Sign in - Google Accounts"},
    {"url": "http://login.microsoftonline.com.account-update.xyz/", "title": "Sign in to your account"},
    {"url": "http://paypal-security-center-update.xyz/signin", "title": "PayPal Account Resolution Center"},
    {"url": "http://amazon-account-billing-hold.top/ap/signin", "title": "Amazon Account Update Required"},
    {"url": "http://192.168.1.100/bank-login/index.php", "title": "Personal Banking Secure Login"}
]

def make_payload(item):
    """Minimal payload per spec: URL and title, dummy form structure."""
    is_https = item["url"].startswith("https://")
    return {
        "url": item["url"],
        "title": item["title"],
        "text_snippet": f"Login to {item['title']}. Please enter credentials.",
        "forms": [
            {
                "action": item["url"],
                "has_password": True,
                "input_names": ["username", "password"]
            }
        ],
        "external_link_ratio": 0.0,
        "favicon_url": "",
        "meta": {"https": is_https, "iframe_count": 0}
    }

def call_analyze(payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        return {"error": str(e)}

REDIRECT_TEST_SET = [
    {"url": "https://parimatchs-sport.top/redirect?aff_c=9988&clickid=test77", "opener": "https://reanime.cz/schedule", "expected_blocked": True, "label": "Parimatch Rogue Popunder (Re:ANIME Case)"},
    {"url": "https://1xbet-promo.click/bonus?subid=123", "opener": "https://reanime.cz/anime", "expected_blocked": True, "label": "1xBet Gambling Popunder"},
    {"url": "https://propellerads.com/zone?pubid=44", "opener": "https://watchfree.test/", "expected_blocked": True, "label": "PropellerAds Rogue Gateway"},
    {"url": "https://clean-pc-virus-found-alert.buzz/warning", "opener": "https://reanime.cz/schedule", "expected_blocked": True, "label": "Scam Scareware Alert Redirect"},
    {"url": "https://github.com/adityabhaker21-star/PhishLens", "opener": "https://reanime.cz/schedule", "expected_blocked": False, "label": "GitHub Repo Navigation (Legitimate)"},
    {"url": "https://google.com/search?q=anime", "opener": "https://reanime.cz/schedule", "expected_blocked": False, "label": "Google Search Link (Legitimate)"},
    {"url": "https://reanime.cz/login", "opener": "https://reanime.cz/schedule", "expected_blocked": False, "label": "Same-Origin Internal Navigation (Legitimate)"},
]

def call_check_redirect(url, opener):
    endpoint = f"http://127.0.0.1:8000/check-redirect?url={urllib.parse.quote(url)}&opener={urllib.parse.quote(opener)}"
    try:
        with urllib.request.urlopen(endpoint, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def run_eval():
    print("=" * 65)
    print(" PhishLens Detection Evaluation Script (30 Test Cases)")
    print("=" * 65)
    print(f"Target Backend: {API_URL}\n")

    # Health check
    test_probe = call_analyze(make_payload(LEGITIMATE_TEST_SET[0]))
    if "error" in test_probe:
        print(f"[!] Backend at {API_URL} is currently unreachable.")
        print("    Ensure Person B's backend is running: `uvicorn app:app --port 8000`")
        print("    Exiting evaluation.")
        sys.exit(1)

    print("Evaluating 20 Legitimate Login Pages (Expected Safe, score < 30)...")
    false_positives = []
    real_correct = 0

    for item in LEGITIMATE_TEST_SET:
        payload = make_payload(item)
        res = call_analyze(payload)
        score = res.get("score")
        verdict = res.get("verdict", "unknown")

        # Safe is score < 30
        if isinstance(score, (int, float)) and score < 30:
            real_correct += 1
            print(f"  [PASS] {item['url'][:45]:<45} -> Score: {score} ({verdict})")
        else:
            false_positives.append((item['url'], score, verdict, res.get("signals", [])))
            print(f"  [FAIL - FP] {item['url'][:45]:<45} -> Score: {score} ({verdict})")

    print("\nEvaluating 10 Phishing Test URLs (Expected Flagged, score >= 30)...")
    misses = []
    phish_correct = 0

    for item in PHISHING_TEST_SET:
        payload = make_payload(item)
        res = call_analyze(payload)
        score = res.get("score", 0)
        verdict = res.get("verdict", "safe")

        if isinstance(score, (int, float)) and score >= 30:
            phish_correct += 1
            print(f"  [PASS] {item['url'][:45]:<45} -> Score: {score} ({verdict})")
        else:
            misses.append((item['url'], score, verdict))
            print(f"  [FAIL - MISS] {item['url'][:45]:<45} -> Score: {score} ({verdict})")

    total_correct = real_correct + phish_correct
    accuracy = (total_correct / 30.0) * 100

    print("\nEvaluating Feature 3: Anti-Redirect & Rogue Popunder Interception...")
    redirect_correct = 0
    for r_test in REDIRECT_TEST_SET:
        r_res = call_check_redirect(r_test["url"], r_test["opener"])
        is_blocked = bool(r_res.get("blocked", False))
        if "error" not in r_res and isinstance(r_res.get("blocked"), bool) and is_blocked == r_test["expected_blocked"]:
            redirect_correct += 1
            status = "BLOCKED" if is_blocked else "ALLOWED"
            print(f"  [PASS] {r_test['label']:<40} -> Action: {status}")
        else:
            print(f"  [FAIL] {r_test['label']:<40} -> Expected {r_test['expected_blocked']} got {is_blocked}")

    print("\n" + "=" * 65)
    print(" EVALUATION SUMMARY")
    print("=" * 65)
    print(f" Phishing Tests:         {total_correct} / 30 ({accuracy:.1f}%)")
    print(f" Redirect Interceptions: {redirect_correct} / {len(REDIRECT_TEST_SET)} ({100 * redirect_correct / len(REDIRECT_TEST_SET):.1f}%)")
    print(f" Legitimate Sites:       {real_correct} / 20 correct ({len(false_positives)} False Positives)")
    print(f" Phishing Sites:         {phish_correct} / 10 flagged ({len(misses)} Misses)")
    print("=" * 65)

    if false_positives:
        print("\nFalse Positives (Real sites mistakenly flagged):")
        for url, score, verd, sigs in false_positives:
            print(f" - {url} (Score {score}, Verdict: {verd})")
            for s in sigs:
                print(f"     triggered: {s.get('id')} ({s.get('points')} pts) - {s.get('detail')}")

    if misses:
        print("\nMisses (Phishing sites not flagged):")
        for url, score, verd in misses:
            print(f" - {url} (Score {score}, Verdict: {verd})")

    return total_correct == 30 and redirect_correct == len(REDIRECT_TEST_SET)

if __name__ == "__main__":
    sys.exit(0 if run_eval() else 1)

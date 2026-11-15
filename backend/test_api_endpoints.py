import urllib.request
import json
import sys

def main():
    print("=" * 65)
    print("      PHISHLENS END-TO-END BACKEND API VERIFICATION")
    print("=" * 65)

    # 1. Health check
    try:
        res = urllib.request.urlopen("http://localhost:8000/", timeout=3).read()
        print("[PASS] 1. Health Check Response:", res.decode("utf-8").strip())
    except Exception as e:
        print("[FAIL] 1. Health check failed:", e)
        sys.exit(1)

    # 2. POST /analyze with fake_payload.json
    try:
        with open("backend/samples/fake_payload.json", "r", encoding="utf-8") as f:
            fake_payload = json.load(f)

        req = urllib.request.Request(
            "http://localhost:8000/analyze",
            data=json.dumps(fake_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        fake_res = json.loads(urllib.request.urlopen(req, timeout=3).read().decode("utf-8"))
        print(f"\n[PASS] 2. Fake Nova Bank KYC Scored: {fake_res['score']} pts -> Verdict: {fake_res['verdict']}")
        print(f"       Scan ID: {fake_res['scan_id']}")
        for s in fake_res.get("signals", []):
            print(f"       + {s['id']} ({s['points']} pts): {s['detail']}")
        assert fake_res["verdict"] == "danger", f"Expected danger, got {fake_res['verdict']}"
        assert fake_res["score"] >= 60, f"Expected score >= 60, got {fake_res['score']}"
    except Exception as e:
        print("[FAIL] 2. Fake payload analysis failed:", e)
        sys.exit(1)

    # 3. POST /explain/{scan_id}
    try:
        scan_id = fake_res["scan_id"]
        req_exp = urllib.request.Request(
            f"http://localhost:8000/explain/{scan_id}",
            data=b"{}",
            headers={"Content-Type": "application/json"}
        )
        exp_res = json.loads(urllib.request.urlopen(req_exp, timeout=5).read().decode("utf-8"))
        print(f"\n[PASS] 3. Explain API for {scan_id}:")
        print(f"       Verdict: {exp_res.get('verdict')}, Confidence: {exp_res.get('confidence')}")
        print(f"       Advice: {exp_res.get('advice')}")
        print("       Reasons:")
        for r in exp_res.get("reasons", []):
            print(f"       - {r}")
        assert "verdict" in exp_res and "reasons" in exp_res and "advice" in exp_res
    except Exception as e:
        print("[FAIL] 3. Explain API failed:", e)
        sys.exit(1)

    # 4. POST /analyze with real_payload.json
    try:
        with open("backend/samples/real_payload.json", "r", encoding="utf-8") as f:
            real_payload = json.load(f)

        req_real = urllib.request.Request(
            "http://localhost:8000/analyze",
            data=json.dumps(real_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        real_res = json.loads(urllib.request.urlopen(req_real, timeout=3).read().decode("utf-8"))
        print(f"\n[PASS] 4. Real Nova Bank Scored: {real_res['score']} pts -> Verdict: {real_res['verdict']}")
        assert real_res["verdict"] == "safe", f"Expected safe, got {real_res['verdict']}"
        assert real_res["score"] < 30, f"Expected score < 30, got {real_res['score']}"
    except Exception as e:
        print("[FAIL] 4. Real payload analysis failed:", e)
        sys.exit(1)

    # 5. GET /events
    try:
        events_res = json.loads(urllib.request.urlopen("http://localhost:8000/events", timeout=3).read().decode("utf-8"))
        print(f"\n[PASS] 5. GET /events returned {len(events_res)} scan events for Live Dashboard.")
        if len(events_res) > 0:
            first = events_res[0]
            print(f"       Top event: URL='{first.get('url')}', Score={first.get('score')}, Verdict='{first.get('verdict')}'")
    except Exception as e:
        print("[FAIL] 5. Events API failed:", e)
        sys.exit(1)

    print("\n" + "=" * 65)
    print("ALL 5 API VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 65)

if __name__ == "__main__":
    main()


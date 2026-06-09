#!/usr/bin/env python3
"""GLM-5.1 baseline vuln scanner — parallel."""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

API_URL = "https://open.bigmodel.cn/api/coding/paas/v4/chat/completions"
API_KEY = "02795750a3db4446b3d675ac755e6c0a.lc9oQDOH86EZ1kwD"
MODEL = "glm-5.1"

with open("/tmp/glm_baseline_prompt.txt") as f:
    SIMPLE_PROMPT = f.read()


def call_glm(prompt: str, max_retries: int = 5) -> str:
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                API_URL,
                data=json.dumps({
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 2000,
                    "temperature": 0.0,
                }).encode(),
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"].get("content", "")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = min(60, 5 * (2 ** attempt))
                time.sleep(wait)
                continue
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return ""


def parse_findings(text: str, filename: str) -> list:
    import re
    findings = []
    blocks = re.findall(r"<vuln>(.*?)</vuln>", text, re.DOTALL)
    if not blocks:
        return findings
    for block in blocks:
        if block.strip().upper() == "NONE":
            continue
        f = {"file": filename}
        for field in ["line", "category", "severity", "confidence", "title", "description"]:
            m = re.search(rf"<{field}>(.*?)</{field}>", block, re.DOTALL)
            if m:
                f[field] = m.group(1).strip()
        if "line" in f:
            try:
                f["line"] = int(f["line"])
            except ValueError:
                pass
        if "confidence" in f:
            try:
                f["confidence"] = float(f["confidence"])
            except ValueError:
                pass
        findings.append(f)
    return findings


def scan_file(f: Path) -> list:
    try:
        code = f.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    if len(code) > 8000:
        code = code[:8000] + "\n\n// TRUNCATED"
    prompt = SIMPLE_PROMPT.replace("{filename}", f.name).replace("{line_number}", "?").replace("{code}", code)
    try:
        text = call_glm(prompt)
    except Exception as e:
        print(f"  {f.name}: API error: {e}", file=sys.stderr)
        return []
    return parse_findings(text, f.name)


def main():
    if len(sys.argv) < 2:
        print("Usage: glm_baseline_par.py <corpus_dir> [output.json] [parallelism]")
        sys.exit(1)
    corpus = Path(sys.argv[1]).resolve()
    out_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/glm_baseline_findings.json")
    parallelism = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    files = sorted(corpus.glob("*.php"))
    print(f"Scanning {len(files)} files with GLM-5.1 baseline (parallel={parallelism})...", file=sys.stderr)

    all_findings = []
    t0 = time.time()
    completed = 0
    with ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = {pool.submit(scan_file, f): f for f in files}
        for fut in as_completed(futures):
            f = futures[fut]
            findings = fut.result()
            all_findings.extend(findings)
            completed += 1
            if completed % 5 == 0 or completed == len(files):
                print(f"  [{completed}/{len(files)}] elapsed={time.time()-t0:.1f}s findings={len(all_findings)}", file=sys.stderr)

    elapsed = time.time() - t0
    result = {
        "tool": "GLM-5.1 baseline (Python parallel)",
        "model": MODEL,
        "files_scanned": len(files),
        "findings_total": len(all_findings),
        "duration_seconds": round(elapsed, 1),
        "findings": all_findings,
    }
    out_file.write_text(json.dumps(result, indent=2))
    print(f"\nDone. {len(all_findings)} findings in {elapsed:.1f}s. Saved to {out_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
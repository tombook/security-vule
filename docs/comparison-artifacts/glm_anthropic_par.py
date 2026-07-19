#!/usr/bin/env python3
"""GLM-5.1 + Anthropic harness prompts — parallel."""
import json
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

API_URL = "https://open.bigmodel.cn/api/coding/paas/v4/chat/completions"
API_KEY = "02795750a3db4446b3d675ac755e6c0a.lc9oQDOH86EZ1kwD"
MODEL = "glm-5.1"

with open("/tmp/glm_anthropic_prompt.txt") as f:
    ANTHROPIC_PROMPT = f.read()


def call_glm(prompt: str, max_retries: int = 5) -> str:
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                API_URL,
                data=json.dumps({
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 3000,
                    "temperature": 0.0,
                }).encode(),
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
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
    findings = []
    blocks = re.findall(r"<finding>(.*?)</finding>", text, re.DOTALL)
    for block in blocks:
        cat_match = re.search(r"<category>(.*?)</category>", block, re.DOTALL)
        if cat_match and cat_match.group(1).strip().lower() == "none":
            continue
        f = {"file": filename}
        for field in ["line", "category", "severity", "confidence", "title", "description",
                      "exploit_scenario", "recommendation"]:
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


def scan_file(idx: int, f: Path, corpus_str: str) -> tuple:
    try:
        code = f.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return (f.name, [])
    if len(code) > 10000:
        code = code[:10000] + "\n\n// TRUNCATED"
    prompt = ANTHROPIC_PROMPT.replace("{focus_area}", f.stem)\
                              .replace("{target_dir}", corpus_str)\
                              .replace("{focus_idx}", f"{idx:02d}")\
                              .replace("{filename}", f.name)\
                              .replace("{code}", code)
    try:
        text = call_glm(prompt)
    except Exception as e:
        print(f"  {f.name}: API error: {e}", file=sys.stderr)
        return (f.name, [])
    return (f.name, parse_findings(text, f.name))


def main():
    if len(sys.argv) < 2:
        print("Usage: glm_anthropic_par.py <corpus_dir> [output.json] [parallelism]")
        sys.exit(1)
    corpus = Path(sys.argv[1]).resolve()
    corpus_str = str(corpus)
    out_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/glm_anthropic_findings.json")
    parallelism = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    files = sorted(corpus.glob("*.php"))
    print(f"Scanning {len(files)} files with GLM-5.1 + Anthropic harness (parallel={parallelism})...", file=sys.stderr)

    all_findings = []
    t0 = time.time()
    completed = 0
    with ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = {pool.submit(scan_file, i, f, corpus_str): f for i, f in enumerate(files, 1)}
        for fut in as_completed(futures):
            name, findings = fut.result()
            all_findings.extend(findings)
            completed += 1
            if completed % 5 == 0 or completed == len(files):
                print(f"  [{completed}/{len(files)}] elapsed={time.time()-t0:.1f}s findings={len(all_findings)}", file=sys.stderr)

    elapsed = time.time() - t0
    result = {
        "tool": "GLM-5.1 + Anthropic harness /vuln-scan prompts (parallel)",
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
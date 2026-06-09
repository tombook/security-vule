#!/usr/bin/env python3
"""Compare all tools on 4 apps (DVWA, bWAPP, sqli-labs, Pikachu)."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, '/tmp')
from compare_tools import evaluate_semgrep, evaluate_bearer, evaluate_glm, evaluate_sv_llm as _evaluate_svllm_dvwa
from compare_per_app import (
    load_gt_for_app, evaluate_bwapp_findings, evaluate_bwapp_glm,
    normalize_bwapp_category, compute_for_tool,
)


def normalize_llm_filename(fname, app):
    fname = fname.replace("/tmp/", "").replace("/root/security-vule/corpus/benchmark/", "")
    if app == "pikachu" and "/" in fname and fname.startswith("vul/"):
        return fname.replace("/", "_")
    return fname


def evaluator_glm_for_app(app):
    if app == "DVWA": return evaluate_glm
    if app == "bWAPP": return evaluate_bwapp_glm
    def _impl(json_path, gt_files):
        d = json.load(open(json_path))
        findings = []
        for f in d.get("findings", []):
            fname = normalize_llm_filename(f.get("file", "?"), app)
            if fname not in gt_files:
                continue
            cat = normalize_bwapp_category(f.get("category", ""))
            findings.append({"file": fname, "line": f.get("line", 0), "category": cat, "confidence": f.get("confidence", 0.5)})
        return {"tool": "GLM-5.1", "findings": findings, "raw_count": len(d.get("findings", []))}
    return _impl


def evaluator_svllm_for_app(app):
    if app == "DVWA": return _evaluate_svllm_dvwa
    from compare_per_app import evaluate_bwapp_sv_llm
    if app == "bWAPP": return evaluate_bwapp_sv_llm
    def _impl(json_path, gt_files):
        d = json.load(open(json_path))
        findings = []
        for f in d.get("findings", []):
            fname = normalize_llm_filename(f.get("file", "?"), app)
            if fname not in gt_files:
                continue
            cat = normalize_bwapp_category(f.get("type", ""))
            findings.append({"file": fname, "line": f.get("line", 0), "category": cat, "confidence": f.get("confidence", 0.5)})
        return {"tool": "security-vule + LLM", "findings": findings, "raw_count": len(d.get("findings", []))}
    return _impl


def evaluator_bearer_for_app(app):
    if app == "DVWA": return evaluate_bearer
    def _impl(json_path, gt_files):
        d = json.load(open(json_path))
        findings = []
        raw_count = 0
        for sev in ["critical", "high", "medium", "low"]:
            for f in d.get(sev, []):
                raw_count += 1
                fname = Path(f.get("filename", "?")).name
                if fname not in gt_files:
                    continue
                title = f.get("title", "")
                cat = normalize_bwapp_category(title)
                findings.append({"file": fname, "line": f.get("line_number", 0), "category": cat})
        return {"tool": "Bearer", "findings": findings, "raw_count": raw_count}
    return _impl


def evaluator_semgrep_for_app(app):
    if app == "DVWA": return evaluate_semgrep
    def _impl(json_path, gt_files):
        d = json.load(open(json_path))
        findings = []
        for r in d.get("results", []):
            fname = Path(r["path"]).name
            if fname not in gt_files:
                continue
            rule = r.get("check_id", "")
            cat = normalize_bwapp_category(rule)
            findings.append({"file": fname, "line": r["start"]["line"], "category": cat})
        return {"tool": "Semgrep", "findings": findings, "raw_count": len(d.get("results", []))}
    return _impl


def evaluator_security_vule_for_app(sv_results, app_name):
    try:
        d = json.load(open(sv_results))
        for app in d:
            if app.get("app") == app_name:
                s = app
                return {"tp": s["tp"], "fp": s["fp"], "fn": s["fn"],
                        "precision": s["precision"], "recall": s["recall"], "f1": s["f1"],
                        "raw_count": s["tp"] + s["fp"]}
    except Exception:
        pass
    return None


def main():
    apps = [
        ("DVWA", "dvwa", False),
        ("bWAPP", "bWAPP", False),
        ("sqli-labs", "sqli-labs", True),
        ("Pikachu", "pikachu", True),
    ]

    tool_files = {
        "Semgrep": {
            "DVWA": "/tmp/semgrep_results.json",
            "bWAPP": "/tmp/semgrep_bwapp.json",
            "sqli-labs": "/tmp/semgrep_sqlilabs.json",
            "Pikachu": "/tmp/semgrep_pikachu.json",
        },
        "Bearer": {
            "DVWA": "/tmp/bearer_results.json",
            "bWAPP": "/tmp/bearer_bwapp.json",
            "sqli-labs": "/tmp/bearer_sqlilabs.json",
            "Pikachu": "/tmp/bearer_pikachu.json",
        },
        "GLM-5.1": {
            "DVWA": "/tmp/glm_baseline_findings.json",
            "bWAPP": "/tmp/glm_bwapp.json",
            "sqli-labs": "/tmp/glm_sqlilabs.json",
            "Pikachu": "/tmp/glm_pikachu.json",
        },
        "security-vule + LLM": {
            "DVWA": "/tmp/sv_llm_round4.json",
            "bWAPP": "/tmp/sv_llm_bwapp.json",
            "sqli-labs": "/tmp/sv_llm_sqlilabs.json",
            "Pikachu": "/tmp/sv_llm_pikachu.json",
        },
    }

    sv_results = "/root/security-vule/corpus/benchmark/results.json"

    all_results = {}
    for app_name, app_key, use_flat in apps:
        gt_files, gt_types = load_gt_for_app(app_key, flat=use_flat)
        all_results[app_name] = {"gt_count": len(gt_files), "tools": {}}

        for tool_name, paths in tool_files.items():
            path = paths[app_name]
            if not os.path.exists(path):
                continue
            if tool_name == "Semgrep":
                eval_fn = evaluator_semgrep_for_app(app_name)
            elif tool_name == "Bearer":
                eval_fn = evaluator_bearer_for_app(app_name)
            elif tool_name == "GLM-5.1":
                eval_fn = evaluator_glm_for_app(app_name)
            elif tool_name == "security-vule + LLM":
                eval_fn = evaluator_svllm_for_app(app_name)
            try:
                t = eval_fn(path, gt_files)
                m = compute_for_tool(t, gt_files, gt_types)
                all_results[app_name]["tools"][tool_name] = m
            except Exception as e:
                all_results[app_name]["tools"][tool_name] = {"error": str(e)}

        sv = evaluator_security_vule_for_app(sv_results, app_name)
        if sv:
            all_results[app_name]["tools"]["security-vule"] = sv

    print(f"\n{'='*90}")
    print(f"COMPREHENSIVE COMPARISON: 4 APPS × 5 TOOLS")
    print(f"{'='*90}\n")

    tool_order = ["Semgrep", "Bearer", "GLM-5.1", "security-vule", "security-vule + LLM"]
    for app_name, _, _ in apps:
        print(f"\n=== {app_name} (GT: {all_results[app_name]['gt_count']} files) ===")
        print(f"{'Tool':<25} {'Raw':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'P%':>6} {'R%':>6} {'F1%':>6}")
        print("-" * 65)
        for tool in tool_order:
            if tool not in all_results[app_name]["tools"]:
                continue
            t = all_results[app_name]["tools"][tool]
            if "error" in t:
                print(f"{tool:<25} ERROR: {t['error']}")
                continue
            print(f"{tool:<25} {t['raw_count']:>6} {t['tp']:>4} {t['fp']:>4} {t['fn']:>4} "
                  f"{t['precision']*100:>5.1f}% {t['recall']*100:>5.1f}% {t['f1']*100:>5.1f}%")

    print(f"\n{'='*90}")
    print(f"F1 LEADERBOARD (4 apps)")
    print(f"{'='*90}")
    print(f"{'App':<14} | {'Semgrep':<10} | {'Bearer':<10} | {'GLM-5.1':<10} | {'SV':<10} | {'SV+LLM':<10}")
    print("-" * 90)
    for app_name, _, _ in apps:
        row = f"{app_name:<14} | "
        for tool in tool_order:
            if tool in all_results[app_name]["tools"]:
                t = all_results[app_name]["tools"][tool]
                row += f"{t.get('f1', 0)*100:>5.1f}%     | "
            else:
                row += f"{'N/A':<10} | "
        print(row)

    out_path = "/tmp/comparison_4apps.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nJSON saved to {out_path}")


if __name__ == "__main__":
    main()
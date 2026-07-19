#!/usr/bin/env python3
"""Build ground-truth.json for bWAPP, sqli-labs, pikachu.

Each repo's vulnerable files are well-known from documentation.
We map filename patterns to vulnerability categories.
"""
import json
import re
from pathlib import Path

GT_BASE = Path("/root/security-vule/corpus/benchmark")


def build_bwapp_gt():
    """bWAPP: each .php file is a standalone vuln example.
    Map filename → category based on bWAPP naming convention.
    """
    bwapp_dir = Path("/tmp/bwapp/bWAPP")
    positives = []
    skipped = []

    # Pattern → category mapping (bWAPP uses prefixes)
    pattern_map = [
        # SQL Injection
        (r"^sqli_", "sql"),
        (r"^sqli_blind", "sql"),
        (r"^sqlitemanager", "sql"),
        (r"^sqli_drupal", "sql"),
        # Command Injection
        (r"^commandi", "shell"),
        (r"^os_commandi", "shell"),
        # XSS
        (r"^xss_", "xss"),
        (r"^xss-", "xss"),
        # CSRF
        (r"^csrf_", "trustbound"),
        # File inclusion
        (r"^directory_traversal", "fileinclude"),
        (r"^lfi_", "fileinclude"),
        (r"^rfi_", "fileinclude"),
        (r"^fi_", "fileinclude"),
        # File upload
        (r"^unrestricted_file_upload", "filewrite"),
        # Open redirect / SSRF
        (r"^unvalidated_redir_fwd", "ssrf"),
        (r"^ssrf", "ssrf"),
        (r"^hostheader", "ssrf"),
        # XXE
        (r"^xxe", "xxe"),
        (r"^xmli_", "xxe"),
        # Broken auth (ba_*) — trust bound / access control
        (r"^ba_", "trustbound"),
        # Buffer overflow
        (r"^bof_", "shell"),
        # Crypto / heartbleed
        (r"^heartbleed", "crypto"),
        # HTTP parameter pollution
        (r"^hpp-", "xss"),
        # SQLi manager
        (r"^ssii", "sql"),
        # Session management (sm_*) — partial
        (r"^smgmt_cookies_httponly", "securecookie"),
        (r"^smgmt_cookies_secure", "securecookie"),
        (r"^smgmt_sessionid_url", "weakrand"),
        (r"^smgmt_admin_portal", "trustbound"),
        (r"^sm_xst", "xss"),
        # Soap / WebServices
        (r"^ws_soap", "xxe"),
        # Clickjacking
        (r"^clickjacking", "trustbound"),
        # Client side
        (r"^aim", "trustbound"),
    ]

    neg_patterns = [
        r"^666$", r"^credits", r"^config\.inc", r"^connect_?[ip]?\.php$", r"^test\.php$",
        r"^install", r"^update\.php$", r"^functions_external", r"^training", r"^top-security",
        r"^captcha_?box", r"^cs_validation", r"^portal\.php$", r"^db\.php$",
        r"^evil/", r"^release", r"^README",
    ]

    seen = set()
    for f in sorted(bwapp_dir.glob("*.php")):
        fname = f.name
        if fname in seen:
            continue
        seen.add(fname)
        # Skip negatives
        is_neg = False
        for np in neg_patterns:
            if re.search(np, fname):
                is_neg = True
                break
        if is_neg:
            continue
        # Match pattern
        for pattern, cat in pattern_map:
            if re.search(pattern, fname):
                positives.append({
                    "category": fname.split(".")[0],
                    "vuln_type": cat,
                    "true_positive_files": [fname],
                    "true_negative_files": [],
                })
                break
        else:
            skipped.append(fname)

    return {
        "positives": positives,
        "skipped": skipped,
    }


def build_sqlilabs_gt():
    """sqli-labs: each Less-N has index.php with SQLi of different types.
    """
    sl_dir = Path("/tmp/sqli-labs")
    positives = []

    # From sqli-labs official documentation
    # Less-1 to Less-4: basic error-based
    # Less-5 to Less-10: blind/error-based variations
    # Less-11 to Less-17: POST-based
    # Less-18 to Less-22: header-based
    # Less-23 to Less-28: filter bypass
    # Less-29 to Less-31: WAF bypass
    # Less-32 to Less-38: charset injection
    # Less-39 to Less-45: stack injection
    # Less-46 to Less-53: order by
    # Less-54 to Less-65: challenge
    # All → sql
    for less_dir in sorted(sl_dir.glob("Less-*")):
        idx_php = less_dir / "index.php"
        if not idx_php.exists():
            continue
        less_name = less_dir.name
        positives.append({
            "category": less_name,
            "vuln_type": "sql",
            "true_positive_files": [f"{less_name}/index.php"],
            "true_negative_files": [],
        })
    return {"positives": positives, "skipped": []}


def build_pikachu_gt():
    """Pikachu: vuln type per vul/<category> subdir.
    """
    pika_dir = Path("/tmp/pikachu")
    vul_dir = pika_dir / "vul"
    positives = []

    # vul subdir → category mapping
    dir_to_cat = {
        "burteforce": "trustbound",  # brute force
        "csrf": "trustbound",
        "dir": "fileinclude",  # directory traversal
        "fileinclude": "fileinclude",
        "infoleak": "info",
        "overpermission": "trustbound",
        "rce": "shell",  # remote code execution
        "sqli": "sql",
        "ssrf": "ssrf",
        "unsafedownload": "fileinclude",
        "unsafeupload": "filewrite",
        "unserilization": "deserialization",
        "urlredirect": "ssrf",
        "xss": "xss",
        "xxe": "xxe",
    }

    for subdir in sorted(vul_dir.iterdir()):
        if not subdir.is_dir():
            continue
        cat_dir = dir_to_cat.get(subdir.name)
        if not cat_dir:
            continue
        for f in sorted(subdir.glob("*.php")):
            if f.name == "config.php":
                continue
            positives.append({
                "category": f"{subdir.name}/{f.stem}",
                "vuln_type": cat_dir,
                "true_positive_files": [f"vul/{subdir.name}/{f.name}"],
                "true_negative_files": [],
            })
    return {"positives": positives, "skipped": []}


def main():
    bwapp = build_bwapp_gt()
    sqli = build_sqlilabs_gt()
    pika = build_pikachu_gt()

    GT_BASE.mkdir(parents=True, exist_ok=True)
    (GT_BASE / "bWAPP").mkdir(exist_ok=True)
    (GT_BASE / "sqli-labs").mkdir(exist_ok=True)
    (GT_BASE / "pikachu").mkdir(exist_ok=True)

    # Save ground truth files in our existing format
    for name, data, total_field in [
        ("bWAPP", bwapp, len(bwapp["positives"])),
        ("sqli-labs", sqli, len(sqli["positives"])),
        ("pikachu", pika, len(pika["positives"])),
    ]:
        out_path = GT_BASE / name / "ground-truth.json"
        out_path.write_text(json.dumps(data["positives"], indent=2))
        # Stats
        by_cat = {}
        for p in data["positives"]:
            by_cat.setdefault(p["vuln_type"], 0)
            by_cat[p["vuln_type"]] += 1
        print(f"{name}: {total_field} positives")
        for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
            print(f"  {cat}: {n}")
        if data["skipped"]:
            print(f"  Skipped (no category matched): {len(data['skipped'])} files")
            print(f"    Examples: {data['skipped'][:5]}")
        print()


if __name__ == "__main__":
    main()
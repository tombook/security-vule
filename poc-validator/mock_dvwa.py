#!/usr/bin/env python3
"""Mock DVWA server for PoC validation.

Replicates DVWA vulnerability response patterns so that PoC exploits can be
verified against it. This is NOT a faithful DVWA clone - it only
replicates the specific response signatures that distinguish a "vulnerable"
response from a "safe" response for each vuln class.
"""
import http.server
import json
import os
import re
import sys
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VULN_DB_PATH = os.path.join(SCRIPT_DIR, "vuln_db.json")
with open(VULN_DB_PATH) as f:
    USERS = json.load(f)
# 5 users
print(f"Loaded {len(USERS)} users for SQL injection sim", file=sys.stderr)

# Mock filesystem
MOCK_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    "config.php": "<?php $secret = 'super_secret_key_123';\n",
    "secret.txt": "TOP_SECRET_DATA\n",
}

# Database state
class MockDB:
    def __init__(self):
        self.users = USERS
        # Also create a 'first users' table for blind SQLi
    def query(self, sql):
        """Mimic mysqli_query behavior. Returns (success, rows, error) tuple."""
        sql_lower = sql.lower()
        # SELECT first_name, last_name FROM users WHERE user_id = '<id>';
        m = re.search(r"user_id\s*=\s*['\"]?(\d+|[^'\";\s]+)['\"]?", sql, re.IGNORECASE)
        if not m and "from users" in sql_lower and "user_id" in sql_lower:
            return (False, [], "You have an error in your SQL syntax")

        # Handle normal id query
        m = re.search(r"user_id\s*=\s*['\"]?(\d+)['\"]?", sql)
        if m and m.group(1).isdigit():
            uid = int(m.group(1))
            if str(uid) in self.users:
                u = self.users[str(uid)]
                return (True, [{"first_name": u["first"], "last_name": u["last"]}], None)
            else:
                return (True, [], None)

        # Detect injection: OR 1=1, OR 'a'='a', UNION SELECT, etc.
        if re.search(r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", sql, re.IGNORECASE):
            return (True, list(self.users.values()), None)
        if re.search(r"or\s+['\"][^\"']+['\"]\s*=\s*['\"]", sql, re.IGNORECASE):
            return (True, list(self.users.values()), None)
        if "union" in sql_lower and "select" in sql_lower:
            return (True, list(self.users.values()), None)

        # Blind SQLi: SLEEP, BENCHMARK
        if re.search(r"sleep\s*\(", sql, re.IGNORECASE):
            return (True, [], "Query took 2.0 seconds")  # Simulate delay
        if re.search(r"benchmark\s*\(", sql, re.IGNORECASE):
            return (True, [], "Query took 5.0 seconds")

        # Generic injection
        return (False, [], f"You have an error in your SQL syntax near '{sql[:30]}'")
    def query_blind(self, sql):
        """Returns (success, response_time_ms, body). For blind SQLi."""
        import time
        t0 = time.time()
        result = self.query(sql)
        elapsed = (time.time() - t0) * 1000
        if re.search(r"sleep\s*\(\s*(\d+)\s*\)", sql, re.IGNORECASE):
            m = re.search(r"sleep\s*\(\s*(\d+)\s*\)", sql, re.IGNORECASE)
            delay = int(m.group(1)) if m else 0
            time.sleep(min(delay, 3))  # Cap at 3s for safety
            return (True, delay * 1000, "User ID exists in the database.")
        return (result[0], elapsed, "User ID exists in the database." if result[0] else "User ID is MISSING from the database.")

DB = MockDB()


class DVWAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        # Pre-canned responses for various paths
        if path == "/" or path == "/index.php":
            self.send_html("""<html><body>
<h1>Damn Vulnerable Web Application (Mock)</h1>
<ul>
<li><a href="vulnerabilities/sqli/?id=1&Submit=Submit">SQL Injection</a></li>
<li><a href="vulnerabilities/sqli_blind/?id=1&Submit=Submit">SQL Injection (Blind)</a></li>
<li><a href="vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit">Command Injection</a></li>
<li><a href="vulnerabilities/xss_r/?name=test">XSS (Reflected)</a></li>
<li><a href="vulnerabilities/xss_s/?txt=test">XSS (Stored)</a></li>
<li><a href="vulnerabilities/fi/?page=include.php">File Inclusion</a></li>
<li><a href="vulnerabilities/upload/">File Upload</a></li>
<li><a href="vulnerabilities/csrf/">CSRF</a></li>
<li><a href="vulnerabilities/open_redirect/?url=index.php">Open Redirect</a></li>
<li><a href="vulnerabilities/cryptography/?cipher=Caesar&shift=3">Cryptography</a></li>
<li><a href="vulnerabilities/weak_id/?id=1">Weak Session ID</a></li>
<li><a href="vulnerabilities/authbypass/?username=admin&password=admin&Login=Login">Auth Bypass</a></li>
</ul>
</body></html>""")
            return

        # SQLi: vulnerable to OR 1=1
        if path == "/vulnerabilities/sqli/" or path == "/vulnerabilities/sqli/index.php":
            return self.handle_sqli(params)
        if path == "/vulnerabilities/sqli_blind/" or path == "/vulnerabilities/sqli_blind/index.php":
            return self.handle_sqli_blind(params)
        if path == "/vulnerabilities/exec/" or path == "/vulnerabilities/exec/index.php":
            return self.handle_exec(params)
        if path == "/vulnerabilities/xss_r/" or path == "/vulnerabilities/xss_r/index.php":
            return self.handle_xss_r(params)
        if path == "/vulnerabilities/xss_s/" or path == "/vulnerabilities/xss_s/index.php":
            return self.handle_xss_s(params)
        if path == "/vulnerabilities/fi/" or path == "/vulnerabilities/fi/index.php":
            return self.handle_fi(params)
        if path == "/vulnerabilities/upload/" or path == "/vulnerabilities/upload/index.php":
            self.send_html("""<html><body>
<h2>Upload your image</h2>
<form enctype="multipart/form-data" action="/vulnerabilities/upload/" method="POST">
<input type="file" name="uploaded" />
<input type="submit" name="Upload" value="Upload" />
</form>
</body></html>""")
            return
        if path == "/vulnerabilities/csrf/" or path == "/vulnerabilities/csrf/index.php":
            return self.handle_csrf(params)
        if path == "/vulnerabilities/open_redirect/" or path == "/vulnerabilities/open_redirect/index.php":
            return self.handle_open_redirect(params)
        if path == "/vulnerabilities/cryptography/" or path == "/vulnerabilities/cryptography/index.php":
            return self.handle_cryptography(params)
        if path == "/vulnerabilities/dynamic_code/" or path == "/vulnerabilities/dynamic_code/index.php":
            return self.handle_dynamic_code(params)
        if path == "/vulnerabilities/weak_id/" or path == "/vulnerabilities/weak_id/index.php":
            return self.handle_weak_id(params)
        if path == "/vulnerabilities/authbypass/" or path == "/vulnerabilities/authbypass/index.php":
            return self.handle_authbypass(params)

        # 404
        self.send_html("<h1>404 Not Found</h1>", status=404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace')
        params = urllib.parse.parse_qs(body)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/vulnerabilities/upload/" or path == "/vulnerabilities/upload/index.php":
            return self.handle_upload_post(params)
        if path == "/vulnerabilities/xss_s/" or path == "/vulnerabilities/xss_s/index.php":
            return self.handle_xss_s_post(params)
        if path == "/vulnerabilities/authbypass/" or path == "/vulnerabilities/authbypass/index.php":
            return self.handle_authbypass(params)

        # Default: re-dispatch as GET
        self.do_GET()

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def handle_sqli(self, params):
        uid = params.get("id", [""])[0]
        # Check if Submit is present (DVWA behavior)
        if "Submit" not in params:
            self.send_html("<html><body><form><input name='id'><input type='submit' name='Submit' value='Submit'></form></body></html>")
            return
        # Try normal query
        query = f"SELECT first_name, last_name FROM users WHERE user_id = '{uid}';"
        success, rows, err = DB.query(query)
        if err:
            self.send_html(f"<pre>ID: {uid}<br />{err}</pre>")
            return
        if rows:
            html = "<pre>"
            for row in rows:
                html += f"ID: {uid}<br />First name: {row['first_name']}<br />Surname: {row['last_name']}<br />"
            html += "</pre>"
            self.send_html(html)
        else:
            self.send_html(f"<pre>ID: {uid}<br />No results.</pre>")

    def handle_sqli_blind(self, params):
        uid = params.get("id", [""])[0]
        if "Submit" not in params:
            self.send_html("<html><body><form><input name='id'><input type='submit' name='Submit' value='Submit'></form></body></html>")
            return
        query = f"SELECT first_name, last_name FROM users WHERE user_id = '{uid}';"
        success, elapsed, body = DB.query_blind(query)
        self.send_html(f"<pre>{body}</pre>")

    def handle_exec(self, params):
        ip = params.get("ip", [""])[0]
        if "Submit" not in params:
            self.send_html("<html><body><form><input name='ip'><input type='submit' name='Submit' value='Submit'></form></body></html>")
            return
        # Simulate shell_exec('ping  -c 4 ' . $ip)
        # Detect command injection: ;, |, &, $()
        cmd = f"ping  -c 4 {ip}"
        if re.search(r"[;|&`$()\n]", ip) or ".." in ip:
            # Simulate command injection
            if "id" in ip.lower() and (";" in ip or "|" in ip or "&" in ip or "$" in ip):
                self.send_html(f"<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n--- 127.0.0.1 ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss</pre>")
                return
            if "ls" in ip:
                self.send_html(f"<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nindex.php\nabout.php\nhelp\n--- 127.0.0.1 ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss</pre>")
                return
            if "cat /etc/passwd" in ip or "cat%20/etc/passwd" in ip.replace(" ", "%20"):
                self.send_html(f"<pre>root:x:0:0:root:/root:/bin/bash\n--- 127.0.0.1 ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss</pre>")
                return
        # Normal ping response
        self.send_html(f"<pre>PING {ip} ({ip}) 56(84) bytes of data.\n--- {ip} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss</pre>")

    def handle_xss_r(self, params):
        name = params.get("name", [""])[0]
        # Vulnerable: directly echoes input
        self.send_html(f"<pre>Hello {name}</pre>")

    def handle_xss_s(self, params):
        # Stored XSS: any txt gets echoed
        txt = params.get("txt", [""])[0]
        if "txt" in params or "btnSign" in params or "mtxMessage" in params:
            self.send_html(f"<pre>{txt}</pre>")
        else:
            self.send_html("<form><input name='txt'><input type='submit' name='btnSign' value='Sign'></form>")

    def handle_fi(self, params):
        page = params.get("page", [""])[0]
        # LFI/RFI vulnerable
        if page.startswith("http"):
            # Remote file inclusion
            self.send_html(f"<html><body><h2>Included from {page}</h2><pre>REMOTE_FILE_CONTENT</pre></body></html>")
            return
        # Local file inclusion
        if ".." in page:
            # Path traversal
            if "passwd" in page or "secret" in page:
                self.send_html(f"<html><body><pre>{MOCK_FS.get('/etc/passwd', 'NOT_FOUND')}</pre></body></html>")
                return
            self.send_html(f"<html><body><pre>FILE_CONTENT for {page}</pre></body></html>")
            return
        self.send_html(f"<html><body><h2>Page: {page}</h2></body></html>")

    def handle_csrf(self, params):
        # CSRF: vulnerable to changing password without token
        if "password_new" in params and "password_conf" in params:
            self.send_html("<pre>Password Changed.</pre>")
        else:
            self.send_html("<form><input name='password_new'><input name='password_conf'><input type='submit' name='Change' value='Change'></form>")

    def handle_open_redirect(self, params):
        url = params.get("url", ["index.php"])[0]
        if url != "index.php":
            # Return 302 redirect
            # Return 200 with body showing redirect URL (PoC test: URL flows to output)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Redirecting to {url}...</body></html>".encode())
        else:
            self.send_html("<a href='?url=http://evil.com'>redirect</a>")

    def handle_cryptography(self, params):
        cipher = params.get("cipher", ["Caesar"])[0]
        shift = int(params.get("shift", ["3"])[0])
        if cipher == "Caesar":
            # Simulate encryption
            self.send_html(f"<pre>Encrypted: KHOOR (shift={shift})</pre>")
        elif cipher == "XOR":
            # XOR with key
            self.send_html("<pre>XOR encrypted with key 'A': 0x90 0x91 0x92</pre>")
        else:
            self.send_html(f"<pre>Encrypted output</pre>")

    def handle_weak_id(self, params):
        uid_str = params.get("id", ["1"])[0]
        try:
            uid = int(uid_str)
        except ValueError:
            uid = 0
        # Predictable session ID via increment
        new_sid = uid + 1
        self.send_html(f"<pre>Session ID: {new_sid}</pre>")

    def handle_authbypass(self, params):
        user = params.get("username", [""])[0]
        pw = params.get("password", [""])[0]
        # Vulnerable to type juggling
        if user == "admin":
            if pw == "0e462097431906509019562988736854" or pw == "0e0" or pw == "" or user == pw:
                self.send_html("<pre>Welcome to the password protected area admin</pre>")
                return
            if pw == "True" or pw == "1" or pw == "0":
                # Loose comparison type juggling
                self.send_html("<pre>Welcome to the password protected area admin</pre>")
                return
        self.send_html("<pre>Login failed</pre>")

    def handle_xss_s_post(self, params):
        return self.handle_xss_s(params)

    def handle_upload_post(self, params):
        # No actual file upload in mock
        self.send_html("<pre>/hackable/uploads/test.png succesfully uploaded!</pre>")

    def handle_dynamic_code(self, params):
        # Simulate eval/assert of user input
        cmd = params.get("cmd", ["phpinfo()"])[0]
        # Return output suggesting code was executed
        body = f"<html><body>Command executed: {cmd}<br>Output: PHP Version 8.1.0</body></html>"
        self.send_html(body)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = http.server.HTTPServer(("0.0.0.0", port), DVWAHandler)
    print(f"Mock DVWA server on port {port}", file=sys.stderr)
    server.serve_forever()

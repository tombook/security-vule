#!/usr/bin/env python3
import subprocess, json, sys
BASE = 'http://localhost:3000/api'

# Login
r = subprocess.run(['curl', '-s', '-X', 'POST', f'{BASE}/auth/login', '-H', 'Content-Type: application/json', '-d', '{"email":"admin@demo.com","password":"Admin@123"}'], capture_output=True, text=True, timeout=5)
tok = json.loads(r.stdout)['access_token']
H = f'Authorization: Bearer {tok}'

# The finding to test
FID = '007fd43b-730e-f50d-1fb5-1ef2fef4eaf5'  # Reflected XSS line 8 in container-min.js

def providers_for(primary):
    """primary = 'glm' or 'minimax' - set as the only one enabled"""
    base = [
        {"id":"ollama-default","provider":"ollama","name":"Ollama (Local)","enabled":False,"priority":1,"apiKey":None,"baseUrl":"http://localhost:11434","defaultModel":"security-vule-poc-v1","modelOptions":["security-vule-poc-v1","llama3.1"],"inputPricePerMTok":0,"outputPricePerMTok":0},
        {"id":"openai-default","provider":"openai","name":"OpenAI","enabled":False,"priority":2,"apiKey":None,"baseUrl":None,"defaultModel":"gpt-4o-mini","modelOptions":["gpt-4o-mini","gpt-4o"],"inputPricePerMTok":0.15,"outputPricePerMTok":0.6},
        {"id":"anthropic-default","provider":"anthropic","name":"Anthropic","enabled":False,"priority":3,"apiKey":None,"baseUrl":None,"defaultModel":"claude-sonnet-4-5","modelOptions":["claude-sonnet-4-5"],"inputPricePerMTok":3,"outputPricePerMTok":15},
        {"id":"deepseek-default","provider":"deepseek","name":"DeepSeek","enabled":False,"priority":5,"apiKey":None,"baseUrl":"https://api.deepseek.com","defaultModel":"deepseek-chat","modelOptions":["deepseek-chat"],"inputPricePerMTok":0.14,"outputPricePerMTok":0.28},
    ]
    if primary == 'glm':
        glm = {"id":"glm-default","provider":"glm","name":"智谱 GLM","enabled":True,"priority":4,"apiKey":"bfbccb17942347ac8b8ff819954b4521.ewvOPoG71Z97vJFx","baseUrl":"https://open.bigmodel.cn/api/coding/paas/v4","defaultModel":"glm-5.2","modelOptions":["glm-5.2"],"inputPricePerMTok":0,"outputPricePerMTok":0}
        minimax = {"id":"custom-minimax","provider":"custom","name":"MiniMax","enabled":False,"priority":5,"apiKey":None,"baseUrl":"https://api.minimaxi.com/v1","defaultModel":"MiniMax-M3","modelOptions":["MiniMax-M3"],"inputPricePerMTok":0,"outputPricePerMTok":0}
    elif primary == 'minimax':
        glm = {"id":"glm-default","provider":"glm","name":"智谱 GLM","enabled":False,"priority":4,"apiKey":None,"baseUrl":"https://open.bigmodel.cn/api/coding/paas/v4","defaultModel":"glm-5.2","modelOptions":["glm-5.2"],"inputPricePerMTok":0,"outputPricePerMTok":0}
        minimax = {"id":"custom-minimax","provider":"custom","name":"MiniMax","enabled":True,"priority":4,"apiKey":"sk-cp-pkhwTAJG2oQ2qVtUbjqj7We5ZWrlerahVYoSZr_Svk6F8P74XvBPOZevxWSzCQawDT-QBb4onoUMqknEmQfvWBgzuQLBkTe77nh-ErhxrfM5ocR_-jinegQ","baseUrl":"https://api.minimaxi.com/v1","defaultModel":"MiniMax-M3","modelOptions":["MiniMax-M3"],"inputPricePerMTok":0,"outputPricePerMTok":0}
    return base + [glm, minimax]

def set_providers(primary):
    payload = providers_for(primary)
    r = subprocess.run(['curl', '-s', '-X', 'PUT', f'{BASE}/provider/v1/settings/llm-providers', '-H', H, '-H', 'Content-Type: application/json', '-d', json.dumps(payload)], capture_output=True, text=True, timeout=10)
    return '"items"' in r.stdout

def get_poc_detail(poc_id):
    r = subprocess.run(['curl', '-s', f'{BASE}/provider/v1/validation/poc/{poc_id}', '-H', H], capture_output=True, text=True, timeout=5)
    return json.loads(r.stdout)

def generate_poc(fid):
    r = subprocess.run(['curl', '-s', '-w', '\n%{http_code}', '-X', 'POST', f'{BASE}/provider/v1/validation/poc/generate', '-H', H, '-H', 'Content-Type: application/json', '-d', json.dumps({"findingId": fid})], capture_output=True, text=True, timeout=180)
    lines = r.stdout.strip().split('\n')
    status = lines[-1]
    body = '\n'.join(lines[:-1])
    return status, json.loads(body) if body else {}

# Get the finding detail
r = subprocess.run(['curl', '-s', f'{BASE}/provider/v1/findings/{FID}', '-H', H], capture_output=True, text=True, timeout=5)
fdetail = json.loads(r.stdout)
print(f'=== Finding under test ===')
print(f"ID:      {FID}")
print(f"Title:   {fdetail.get('title')}")
print(f"Severity: {fdetail.get('severity')}")
print(f"File:    dvwa{...}")
print(f"Line:    {fdetail.get('start_line')}")
snippet = fdetail.get('code_snippet', '') or ''
print(f"Code snippet:\n{snippet}")
print()

# Phase 1: GLM only
print('--- PHASE 1: GLM only ---')
print('Setting up: GLM enabled, MiniMax disabled')
ok = set_providers('glm')
print('Save:', 'OK' if ok else 'FAILED')
import time
print('Generating PoC...')
t0 = time.time()
status, d = generate_poc(FID)
t_glm = time.time() - t0
glm_poc_id = d.get('id', '?')
print(f'HTTP {status} in {t_glm:.1f}s, PoC: {glm_poc_id[:14]}, reused={d.get("reused", False)}')

# Show GLM PoC detail
detail1 = get_poc_detail(glm_poc_id)
glm_script = detail1.get('pocScript', '')
print(f'Provider: {detail1.get("llmProvider", "?")}, Model: {detail1.get("llmModel", "?")}')
print(f'Cost:     ${detail1.get("costUsd", 0):.6f}')
print(f'Script:   {len(glm_script)} chars')

# Phase 2: MiniMax only
print()
print('--- PHASE 2: MiniMax only ---')
print('Setting up: MiniMax enabled, GLM disabled')
ok = set_providers('minimax')
print('Save:', 'OK' if ok else 'FAILED')
print('Generating PoC...')
t0 = time.time()
status, d = generate_poc(FID)
t_mm = time.time() - t0
mm_poc_id = d.get('id', '?')
print(f'HTTP {status} in {t_mm:.1f}s, PoC: {mm_poc_id[:14]}')

detail2 = get_poc_detail(mm_poc_id)
mm_script = detail2.get('pocScript', '')
print(f'Provider: {detail2.get("llmProvider", "?")}, Model: {detail2.get("llmModel", "?")}')
print(f'Cost:     ${detail2.get("costUsd", 0):.6f}')
print(f'Script:   {len(mm_script)} chars')

# Comparison
print()
print('====================================================')
print('   双 LLM 漏洞挖掘对比 (Dual-LLM A/B Test)        ')
print('====================================================')
print()
print(f'Finding:  Reflected XSS via innerHTML')
print(f'Metric          {"GLM glm-5.2":>18s} {"MiniMax-M3":>18s}')
print('-' * 60)
print(f'脚本长度         {str(len(glm_script))+" chars":>18s} {str(len(mm_script))+" chars":>18s}')
print(f'生成耗时         {f"{t_glm:.1f}s":>18s} {f"{t_mm:.1f}s":>18s}')

# Quality signals
def extract_python_code(s):
    """Strip markdown fences and count python code features"""
    import re
    if not s: return {}
    # Remove thinking blocks
    s_clean = re.sub(r'```\w*\n?', '', s).strip()
    return {
        'has_http_server': 'http.server' in s or 'BaseHTTPRequestHandler' in s,
        'has_socket_server': 'socketserver' in s or 'SocketServer' in s,
        'has_requests_lib': 'import requests' in s or 'requests.' in s,
        'has_argparse': 'argparse' in s,
        'has_class': 'class ' in s and ':' in s,
        'has_main_fn': 'def main' in s or "if __name__ == '__main__'" in s or 'def main(' in s,
        'has_xss_payload': any(p in s.lower() for p in ['alert(', 'onerror=', 'onload=', '<svg', '<script>', '<iframe']),
        'has_docstring': '"""' in s or "'''" in s,
        'has_error_handling': 'try:' in s or 'except' in s,
    }

glm_q = extract_python_code(glm_script)
mm_q = extract_python_code(mm_script)
print()
print(f'代码特性:')
for key, label in [('has_http_server', 'HTTP 服务器'), ('has_requests_lib', 'requests 库'), ('has_class', 'OOP 类'), ('has_main_fn', 'main entry'), ('has_xss_payload', 'XSS payload'), ('has_error_handling', '错误处理')]:
    g = '✓' if glm_q.get(key) else '✗'
    m = '✓' if mm_q.get(key) else '✗'
    print(f'  {label:18s}    {"✓" if glm_q.get(key) else "✗"}    {"✓" if mm_q.get(key) else "✗"}')

print()
print('===== GLM glm-5.2 完整 PoC =====')
print(glm_script)
print()
print('===== MiniMax-M3 完整 PoC =====')
print(mm_script)

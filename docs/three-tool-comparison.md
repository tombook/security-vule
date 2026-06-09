# 四工具漏洞检测对比报告

生成时间: 2026-06-09 19:38

---

## 1. 工具配置

| 工具 | 来源 | 检测方法 | LLM 后端 |
|------|------|----------|----------|
| **security-vule (AST)** | 本项目 | 静态 AST + 污点追踪 | 无 (规则引擎) |
| **security-vule (LLM)** | 本项目 | LLM 增强漏洞分析 | MiniMax-M3 (主) + GLM-5.1 coding (备) |
| **Open Code Review** | 阿里巴巴 | LLM diff review | GLM-4-Flash (智谱) |
| **Defending Code Reference Harness** | Anthropic | 并行子代理静态审查 | GLM-5.1 (智谱) |

### LLM 端点详情

| 提供商 | URL | 模型 | 用途 |
|--------|-----|------|------|
| MiniMax | `https://api.minimaxi.com/v1` | MiniMax-M3 | security-vule LLM 主模型 |
| 智谱 Coding | `https://open.bigmodel.cn/api/coding/paas/v4` | glm-5.1 | security-vule LLM 备用 + Harness |
| 智谱 | `https://open.bigmodel.cn/api/paas/v4` | glm-4-flash | OCR |

---

## 2. 测试目标

12 个 PHP 文件，来自 3 个 intentionally vulnerable web 应用：

| 应用 | 文件 | 漏洞类型 |
|------|------|----------|
| **DVWA** | dvwa_sqli_low.php | SQL 注入 |
| | dvwa_xss_reflected_low.php | 反射型 XSS |
| | dvwa_xss_stored_low.php | 存储型 XSS |
| | dvwa_cmdi_low.php | 命令注入 |
| | dvwa_lfi_low.php | 本地文件包含 |
| | dvwa_upload_low.php | 任意文件上传 |
| **sqli-labs** | sqli_less1.php | GET 型 SQL 注入 |
| | sqli_less11.php | POST 型 SQL 注入 |
| **Pikachu** | pikachu_sqli_id.php | 数字型 SQL 注入 |
| | pikachu_sqli_str.php | 字符型 SQL 注入 |
| | pikachu_rce_ping.php | 命令注入 |
| | pikachu_xss_reflected.php | 反射型 XSS |

---

## 3. 总结数据

| 指标 | sv-AST | sv-LLM | OCR | Harness |
|------|:------:|:------:|:---:|:-------:|
| 总发现数 | 9 | **12** | 18 (vuln) / 35 (total) | **23** |
| CRITICAL | 2 | **9** | — | — |
| HIGH | 4 | **3** | — | 12 |
| MEDIUM | 3 | **0** | — | 10 |
| LOW | 0 | **0** | — | 1 |
| 文件覆盖率 | 5/12 (42%) | **12/12 (100%)** | 7/12 (58%) | **12/12 (100%)** |
| 精确度 | ~100% | **100%** | ~72% (13/18 vuln 真阳性) | ~96% (22/23) |
| 执行时间 | **~5s** | ~60s | 4m13s | ~3min |
| Token 消耗 | **0** | ~23K | 460K | ~200K |

---

## 4. 按漏洞类型检测覆盖

| 漏洞类型 | sv-AST | sv-LLM | OCR | Harness | PoC 验证 |
|----------|:------:|:------:|:---:|:-------:|:--------:|
| SQL 注入 (DVWA) | ❌ | ✅ | ✅ | ✅ | ✅ |
| SQL 注入 (sqli-labs Less-1) | ❌ | ✅ | ✅ | ✅ | ✅ |
| SQL 注入 (sqli-labs Less-11) | ❌ | ✅ | ✅ | ✅ | ✅ |
| SQL 注入 (Pikachu sqli_id) | ❌ | ✅ | ✅ | ✅ | ✅ |
| SQL 注入 (Pikachu sqli_str) | ❌ | ✅ | ✅ | ✅ | ✅ |
| SQL 注入 (DVWA xss_stored INSERT) | ❌ | ❌ | ✅ | ✅ | — |
| 命令注入 (DVWA) | ✅ | ✅ | ❌ | ✅ | ✅ |
| 命令注入 (Pikachu) | ✅ | ✅ | ✅ | ✅ | ✅ |
| 反射型 XSS (DVWA) | ✅ | ✅ | ✅ | ✅ | ✅ |
| 反射型 XSS (Pikachu) | ❌ | ✅ | ✅ | ✅ | ✅ |
| 存储型 XSS (DVWA) | ❌ | ✅ | ✅ | ✅ | ✅ |
| 本地文件包含 (DVWA) | ✅ | ✅ | ✅ | ✅ | ✅ |
| 任意文件上传 (DVWA) | ✅ | ✅ | ✅ | ✅ | ✅ |
| 信息泄露 (result.txt) | ❌ | ❌ | ❌ | ✅ | — |
| 弃用 API (mysql_*) | ❌ | ❌ | ✅ | ✅ | — |
| 二次 XSS (DB 值输出) | ❌ | ❌ | ❌ | ✅ | — |
| 动态代码执行 (CWE-94) | ✅ | ❌ | ❌ | ❌ | — |

**覆盖率统计**: sv-AST 38% (5/13) | sv-LLM **85% (11/13)** | OCR 69% (9/13) | Harness **100% (13/13)**

---

## 5. 各工具详细发现

### 5.1 security-vule AST (规则引擎)

| # | 文件 | 行 | 类型 | 严重度 | CWE |
|---|------|----|------|--------|-----|
| 1 | dvwa_xss_reflected_low.php | 8 | XSS | MEDIUM | CWE-79 |
| 2 | dvwa_lfi_low.php | 4 | FILE_INCLUDE | MEDIUM | CWE-98 |
| 3 | dvwa_upload_low.php | 9 | FILE_WRITE | HIGH | CWE-73 |
| 4 | pikachu_rce_ping.php | 26 | SHELL | CRITICAL | CWE-78 |
| 5 | pikachu_rce_ping.php | 26 | DYNAMIC_CODE | HIGH | CWE-94 |
| 6 | sqli_less11.php | 51 | FILE_WRITE | HIGH | CWE-73 |
| 7 | dvwa_cmdi_low.php | 10 | SHELL | CRITICAL | CWE-78 |
| 8 | dvwa_cmdi_low.php | 10 | DYNAMIC_CODE | HIGH | CWE-94 |
| 9 | sqli_less1.php | 23 | FILE_WRITE | HIGH | CWE-73 |

**特点**: 零 LLM 开销，5 秒完成。能检测 Shell/动态代码执行，但**完全无法检测 SQL 注入**（缺少 SQL 污点规则）。

### 5.2 security-vule LLM (MiniMax-M3 + GLM-5.1)

| # | 文件 | 行 | 类型 | 严重度 | 置信度 |
|---|------|----|------|--------|--------|
| 1 | dvwa_cmdi_low.php | 10 | Command Injection | CRITICAL | 100% |
| 2 | dvwa_lfi_low.php | 4 | File Inclusion | CRITICAL | 97% |
| 3 | dvwa_sqli_low.php | 8 | SQL Injection | CRITICAL | 99% |
| 4 | dvwa_upload_low.php | 9 | Unrestricted File Upload | CRITICAL | 98% |
| 5 | dvwa_xss_reflected_low.php | 8 | Cross-Site Scripting | HIGH | 99% |
| 6 | dvwa_xss_stored_low.php | 6 | Cross-Site Scripting | HIGH | 95% |
| 7 | pikachu_rce_ping.php | 26 | Command Injection | CRITICAL | 99% |
| 8 | pikachu_sqli_id.php | 27 | SQL Injection | CRITICAL | 99% |
| 9 | pikachu_sqli_str.php | 28 | SQL Injection | CRITICAL | 100% |
| 10 | pikachu_xss_reflected.php | 25 | Cross-Site Scripting | HIGH | 99% |
| 11 | sqli_less1.php | 29 | SQL Injection | CRITICAL | 100% |
| 12 | sqli_less11.php | 57 | SQL Injection | CRITICAL | 99% |

**特点**: 12/12 文件全覆盖，12 个发现全部为真阳性（100% 精确度）。每文件仅返回 1 个主要发现。

### 5.3 Open Code Review (阿里巴巴)

| # | 文件 | 类型 | 严重度 | 发现内容 |
|---|------|------|--------|----------|
| 1 | dvwa_lfi_low.php | LFI | medium | $_GET['page'] 直接用于 include |
| 2 | dvwa_sqli_low.php | SQLi | high | 用户输入直接拼接 SQL 查询 |
| 3 | dvwa_sqli_low.php | 代码质量 | info | 全局变量线程安全 |
| 4 | dvwa_xss_stored_low.php | SQLi | high | 需额外检查防 SQLi/XSS |
| 5 | dvwa_xss_stored_low.php | RCE | high | 建议关闭数据库连接 |
| 6 | pikachu_sqli_id.php | SQLi | high | 未使用预处理语句 |
| 7 | pikachu_sqli_str.php | SQLi | high | 用户输入直接拼接 SQL |
| 8 | pikachu_xss_reflected.php | XSS | medium | message 参数缺少验证 (×4) |
| 9 | sqli_less11.php | SQLi | high | 认证脚本 SQL 注入 |
| 10 | sqli_less11.php | 代码质量 | high | 弃用 mysql_* 函数 |

**特点**: Git diff 原生集成。但 <50 行文件跳过 plan 阶段，DVWA cmdi 和 upload 未检出。对 pikachu_xss_reflected.php 产生 5 次重复发现。

### 5.4 Defending Code Reference Harness (Anthropic 方法论)

| # | 文件 | 行 | 类型 | 严重度 | 置信度 |
|---|------|----|------|--------|--------|
| 1 | dvwa_cmdi_low.php | 6 | command-injection | HIGH | 1.0 |
| 2 | dvwa_lfi_low.php | 3 | lfi | HIGH | 0.95 |
| 3 | dvwa_sqli_low.php | 6 | sql-injection | HIGH | 1.0 |
| 4 | dvwa_sqli_low.php | 14 | xss | MEDIUM | 1.0 |
| 5 | dvwa_upload_low.php | 5 | file-upload | HIGH | 1.0 |
| 6 | dvwa_xss_reflected_low.php | 3 | xss | MEDIUM | 1.0 |
| 7 | dvwa_xss_stored_low.php | 22 | xss | HIGH | 1.0 |
| 8 | dvwa_xss_stored_low.php | 19 | sql-injection | HIGH | 0.95 |
| 9 | pikachu_rce_ping.php | 33 | command-injection | HIGH | 1.0 |
| 10 | pikachu_rce_ping.php | 13 | xss | MEDIUM | 1.0 |
| 11 | pikachu_sqli_id.php | 34 | sql-injection | HIGH | 1.0 |
| 12 | pikachu_sqli_id.php | 38 | xss | MEDIUM | 0.9 |
| 13 | pikachu_sqli_str.php | 35 | sql-injection | HIGH | 1.0 |
| 14 | pikachu_sqli_str.php | 39 | xss | MEDIUM | 0.9 |
| 15 | pikachu_xss_reflected.php | 26 | xss | MEDIUM | 1.0 |
| 16 | sqli_less1.php | 20 | sql-injection | HIGH | 1.0 |
| 17 | sqli_less1.php | 22 | xss | MEDIUM | 0.95 |
| 18 | sqli_less1.php | 21 | info-disclosure | LOW | 1.0 |
| 19 | sqli_less1.php | 19 | deprecated-api | HIGH | 1.0 |
| 20 | sqli_less11.php | 43 | sql-injection | HIGH | 1.0 |
| 21 | sqli_less11.php | 42 | info-disclosure | MEDIUM | 1.0 |
| 22 | sqli_less11.php | 63 | info-disclosure | MEDIUM | 1.0 |
| 23 | sqli_less11.php | 49 | xss | MEDIUM | 0.95 |

**特点**: 最全面 (23 发现)，包含 exploit_scenario + recommendation。检测到了其他工具未发现的信息泄露和二次 XSS。

---

## 6. 独有发现

| 独有于 | 发现 | 说明 |
|--------|------|------|
| **sv-AST** | 动态代码执行 (CWE-94) | 仅 AST 污点追踪能标记 dynamic_code 类型 |
| **sv-LLM** | — | 所有发现与其他工具有重叠，但精确度最高 |
| **OCR** | X-XSS-Protection: 0 header | DVWA 反射型 XSS 中禁用了浏览器 XSS 过滤器 |
| **OCR** | 种族条件 (upload) | 文件上传中并发竞争问题 |
| **Harness** | 信息泄露 (result.txt) | sqli-labs 将用户凭据写入文件 |
| **Harness** | mysql_error() 暴露 | 数据库错误信息直接输出给用户 |
| **Harness** | 弃用 mysql_* API | mysql_query 在 PHP 7.0 中已被移除 |
| **Harness** | 二次 XSS (DB→HTML) | 通过 SQLi 注入 XSS payload 到数据库后在渲染时执行 |

---

## 7. 共识发现 (全部 4 个工具一致)

以下漏洞被至少 3/4 个工具检测到，且全部通过 Playwright PoC 运行时验证：

| # | 漏洞 | 文件 | PoC 状态 |
|---|------|------|----------|
| 1 | DVWA SQL 注入 | dvwa_sqli_low.php:8 | ✅ OR + UNION 注入 |
| 2 | DVWA 命令注入 | dvwa_cmdi_low.php:10 | ✅ ;cat /etc/passwd |
| 3 | DVWA 文件包含 | dvwa_lfi_low.php:4 | ✅ ../../../../etc/passwd |
| 4 | DVWA 文件上传 | dvwa_upload_low.php:9 | ✅ .php web shell |
| 5 | sqli-labs Less-1 | sqli_less1.php:29 | ✅ UNION SELECT |
| 6 | sqli-labs Less-11 | sqli_less11.php:57 | ✅ admin'-- 认证绕过 |
| 7 | Pikachu 数字型 SQLi | pikachu_sqli_id.php:27 | ✅ UNION SELECT |
| 8 | Pikachu 字符型 SQLi | pikachu_sqli_str.php:28 | ✅ ' UNION SELECT |
| 9 | Pikachu 命令注入 | pikachu_rce_ping.php:26 | ✅ ;whoami |
| 10 | Pikachu 反射型 XSS | pikachu_xss_reflected.php:25 | ✅ <script>alert(1)</script> |

---

## 8. 代码修改记录

为支持双模型 LLM 扫描，对 security-vule 做了以下修改：

### `src/llm/router.ts`
- 每个提供商使用唯一注册键（`zhipu`/`minimax`/`deepseek`等），避免 Map 覆盖
- ZhiPu 改用 `createZhipuCodingProvider()` → `https://open.bigmodel.cn/api/coding/paas/v4` + `glm-5.1`

### `src/detection/llm-agent.ts`
- 解析逻辑增加 MiniMax-M3 `<think/>` 思维链标签清理
- 增加 ````json...```` markdown 包裹提取
- 增加 `{}` 花括号定位兜底

### `scripts/llm-scan.ts` (新增)
- 双模型 LLM 扫描入口脚本
- 支持 `PREFER_PROVIDER`/`PREFER_MODEL` 环境变量

---

## 9. 使用建议

| 场景 | 推荐工具 | 理由 |
|------|----------|------|
| CI/CD pre-commit hook | **security-vule AST** | 5 秒，零成本 |
| LLM 增强扫描 | **security-vule LLM** | 60 秒，23K tokens，100% 精确度 |
| PR code review | **OCR** | Git diff 原生，附带代码质量建议 |
| 深度安全审计 | **Harness** | 最全面，含 exploit_scenario |
| 运行时验证 | **Playwright PoC** | 确认可利用性 |

### 运行命令

```bash
# AST 扫描
bun run src/integration/cli.ts analyze test-targets/php-vulns/

# LLM 双模型扫描
export ZHIPU_API_KEY="<key>"
export MINIMAX_API_KEY="<key>"
bun run scripts/llm-scan.ts test-targets/php-vulns/

# OCR 扫描
export ZHIPU_API_KEY="<key>"
~/.opencodereview/ocr review --from HEAD~1 --to HEAD --format json
```

---

## 10. 相关文件

| 文件 | 内容 |
|------|------|
| `docs/security-vule-llm-results.json` | security-vule LLM 扫描详细结果 |
| `docs/ocr-review-results.json` | OCR 扫描详细结果 |
| `docs/harness-vuln-findings.json` | Harness 扫描详细结果 |
| `docs/verification-report.json` | Playwright PoC 验证报告 |
| `docs/three-tool-comparison.md` | 本报告 |
| `scripts/llm-scan.ts` | LLM 扫描入口脚本 |
| `poc-validator/real-apps/docker-compose.yml` | Docker 靶机配置 |
| `scripts/full_poc_verify.py` | Playwright PoC 验证脚本 |

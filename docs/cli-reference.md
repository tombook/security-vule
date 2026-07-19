# security-vule CLI 参考

## 总览

security-vule 是一个数据驱动的白盒漏洞挖掘系统，结合静态分析、LLM 增强和运行时 PoC 验证，提供高精度的 Web 应用漏洞检测能力。

## 命令列表

### scan - 静态分析扫描

对指定目录或文件执行静态分析扫描，支持多种输出格式和过滤选项。

#### 用法

```bash
security-vule scan <path> [选项]
```

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--sarif` | SARIF 2.1.0 输出格式，用于 GitHub/GitLab 代码扫描集成 | 关闭 |
| `--baseline FILE` | 跳过基线文件中已存在的漏洞（增量 CI 扫描） | 无 |
| `--diff` | 仅显示基线之后新增的漏洞 | 关闭 |
| `--output FILE`, `-o FILE` | 将结果写入文件而非标准输出 | 标准输出 |
| `--min-confidence N` | 按置信度过滤（0 到 1 之间） | 0 |
| `--status=LIST` | 按分诊状态过滤，逗号分隔 | `open,confirmed` |
| `--state-file F` | 指定状态文件路径 | `<target>/.vule-state.json` |
| `--sca=semgrep,trivy` | 运行外部 SCA 工具（可选，逗号分隔） | 无 |
| `--with-poc` | 扫描后自动运行 PoC 验证并合并结果 | 关闭 |
| `--poc-target=mock\|real\|none` | PoC 验证目标类型 | `none` |
| `--poc-auto-confirm` | 自动将 PoC 验证通过的漏洞状态设为 confirmed | 关闭 |
| `--help`, `-h` | 显示帮助信息 | - |

#### 输出结构（JSON）

```json
{
  "summary": {
    "total_findings": 10,
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 1,
    "by_severity": { "critical": 2, "high": 3, "medium": 4, "low": 1 },
    "poc_verified": 1,
    "poc_not_exploited": 2,
    "files_scanned": 50
  },
  "mermaid": {
    "severity_pie": "pie title 漏洞严重程度分布\n    \"Critical\" : 2\n    \"High\" : 3\n    \"Medium\" : 4\n    \"Low\" : 1",
    "poc_pie": "pie title PoC 验证状态分布\n    \"Verified\" : 1\n    \"Not Exploited\" : 2\n    \"Unconfirmed\" : 7"
  },
  "target": "./src",
  "files_scanned": 50,
  "total_findings": 10,
  "shown_findings": 10,
  "triage": {
    "open": 5,
    "confirmed": 3,
    "fixed": 1,
    "wontfix": 0,
    "false_positive": 1
  },
  "findings": [ ... ]
}
```

#### 示例

```bash
# 基本扫描（JSON 输出）
security-vule scan ./src

# SARIF 格式输出，用于 GitHub Code Scanning
security-vule scan ./src --sarif --output results.sarif

# 增量扫描（仅显示新增漏洞）
security-vule scan ./src --baseline baseline.json --diff

# 带 PoC 验证的扫描（mock 目标）
security-vule scan ./src --with-poc --poc-target=mock --output findings.json

# 自动确认 PoC 验证通过的漏洞
security-vule scan ./src --with-poc --poc-target=mock --poc-auto-confirm

# 按状态和置信度过滤
security-vule scan ./src --status=open,confirmed --min-confidence 0.5
```

---

### verify-poc - PoC 运行时验证

对扫描结果执行运行时 PoC 验证，通过实际执行漏洞利用来验证漏洞的真实性。

#### 用法

```bash
security-vule verify-poc <findings.json> [选项]
```

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--target=mock\|dvwa\|bwapp\|sqlilabs\|pikachu\|auto\|none` | 目标应用类型 | `auto`（自动检测可达目标） |
| `--output FILE`, `-o FILE` | 验证结果输出路径 | `/tmp/sv_poc_verified.json` |
| `--python PY` | Python 解释器路径 | `python3` |
| `--script PATH` | verify_poc.py 脚本路径 | `poc-validator/verify_poc.py` |
| `--timeout-ms N` | 进程超时时间（毫秒） | `180000` |
| `--help`, `-h` | 显示帮助信息 | - |

#### 示例

```bash
# 基本验证（自动检测目标）
security-vule verify-poc ./findings.json

# 指定 mock 目标
security-vule verify-poc ./findings.json --target=mock --output verified.json

# 指定 DVWA 目标
security-vule verify-poc ./findings.json --target=dvwa
```

---

### generate-poc - LLM 生成 PoC 候选

使用 LLM 为扫描发现的漏洞生成 PoC 候选代码（不执行）。

#### 用法

```bash
security-vule generate-poc <findings.json> [选项]
```

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--finding-id ID` | 仅为指定漏洞生成 PoC | 全部漏洞 |
| `--output FILE`, `-o FILE` | 输出 JSON 文件路径 | `<input>.poc-gen.json` |
| `--model MODEL` | LLM 模型 ID（如 gpt-4o-mini、glm-4） | 路由器默认 |
| `--provider NAME` | 首选提供商（openai、anthropic、ollama 等） | 路由器默认 |
| `--help`, `-h` | 显示帮助信息 | - |

#### 示例

```bash
# 为所有漏洞生成 PoC 候选
security-vule generate-poc ./findings.json --output poc-candidates.json

# 为指定漏洞生成 PoC
security-vule generate-poc ./findings.json --finding-id VULN-xxx --output single-poc.json

# 使用指定模型
security-vule generate-poc ./findings.json --model glm-4 --provider openai
```

---

### state - Finding 状态管理

管理漏洞的分诊状态，支持状态跟踪、批量清理和导入导出。

#### 用法

```bash
security-vule state <子命令> [选项]
```

#### 子命令

| 子命令 | 描述 |
|--------|------|
| `list` | 列出所有状态条目 |
| `set <fp> <st>` | 设置单个指纹的状态（支持 `--note` 添加备注） |
| `clean` | 批量清理状态，支持按状态和时间过滤 |
| `export --output FILE` | 导出状态数据 |
| `import --input FILE [--merge]` | 导入状态数据 |

#### 状态类型

- `open` - 新发现，待处理
- `confirmed` - 已确认存在
- `fixed` - 已修复
- `wontfix` - 不修复（接受风险）
- `false_positive` - 误报

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--state-file FILE` | 覆盖状态文件位置 | `<target>/.vule-state.json` |

#### clean 子命令选项

| 选项 | 描述 |
|------|------|
| `--fixed` | 清理已修复状态的条目 |
| `--confirmed` | 清理已确认状态的条目 |
| `--wontfix` | 清理不修复状态的条目 |
| `--false-positive` | 清理误报状态的条目 |
| `--open` | 清理待处理状态的条目 |
| `--older-than Nd` | 仅清理 N 天前的条目 |

#### 示例

```bash
# 列出所有状态
security-vule state list

# 设置单个漏洞状态
security-vule state set src/x.php:10:sqli confirmed --note "手动验证确认"

# 清理 30 天前的已修复条目
security-vule state clean --fixed --older-than 30d

# 导出状态
security-vule state export --output state-export.json

# 导入状态（合并模式）
security-vule state import --input state-export.json --merge
```

---

### usage - AI 用量报告

生成 LLM 用量汇总报告，支持按多个维度分组和多种时间范围。

#### 用法

```bash
security-vule usage report [选项]
```

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--since=30d\|7d\|24h\|DATE` | 起始时间 | 全部时间 |
| `--until=now\|DATE` | 结束时间 | `now` |
| `--by=capability\|provider\|model\|day\|project` | 分组维度 | `capability` |
| `--format=json\|markdown` | 输出格式 | `json` |
| `--usage-file PATH` | Usage JSONL 文件路径 | `.vule-usage.jsonl` |
| `--help`, `-h` | 显示帮助信息 | - |

#### 示例

```bash
# 查看全部用量（JSON）
security-vule usage report

# 近 30 天按模型分组
security-vule usage report --since=30d --by=model

# Markdown 格式输出，按提供商分组
security-vule usage report --since=7d --by=provider --format=markdown

# 指定时间段
security-vule usage report --since=2026-01-01 --until=2026-06-01
```

---

### audit - 审计日志

审计日志管理，支持事件查询、导出和哈希链完整性验证。

#### 用法

```bash
security-vule audit <子命令> [选项]
```

#### 子命令

| 子命令 | 描述 |
|--------|------|
| `list` | 列出审计事件 |
| `export` | 导出审计日志 |
| `verify` | 验证哈希链完整性 |

#### list 子命令选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--action=NAME` | 按操作类型过滤 | 全部 |
| `--since=7d\|DATE` | 起始时间 | 全部 |
| `--until=now\|DATE` | 结束时间 | `now` |
| `--limit=N` | 最大事件数 | `100` |
| `--audit-file PATH` | 审计文件路径 | 默认路径 |

#### export 子命令选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--output FILE`, `-o FILE` | 输出文件路径 | 必填 |
| `--audit-file PATH` | 审计文件路径 | 默认路径 |

#### verify 子命令选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--audit-file PATH` | 审计文件路径 | 默认路径 |

#### 示例

```bash
# 列出最近 100 条审计事件
security-vule audit list

# 过滤扫描相关事件
security-vule audit list --action=scan.completed --since=7d

# 导出全部审计日志
security-vule audit export --output audit-export.json

# 验证哈希链完整性
security-vule audit verify
```

---

### threat-model - 威胁建模

基于 STRIDE 方法论生成威胁模型，支持自动生成数据流图（DFD）。

#### 用法

```bash
security-vule threat-model <path> [选项]
```

#### 选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--output FILE`, `-o FILE` | 输出文件 | 标准输出 |
| `--with-dfd` | 包含数据流图（Mermaid 格式） | 关闭 |
| `--help`, `-h` | 显示帮助信息 | - |

#### 示例

```bash
# 基本威胁模型
security-vule threat-model ./src

# 包含 DFD 图的威胁模型
security-vule threat-model ./src --with-dfd --output threat-model.json
```

---

### version - 版本信息

显示 security-vule 的版本号。

#### 用法

```bash
security-vule version
```

#### 示例

```bash
security-vule version
# 输出: security-vule 0.1.0
```

---

## 退出码

| 退出码 | 描述 |
|--------|------|
| `0` | 执行成功，无 critical 级别漏洞 |
| `1` | 执行成功，但发现 critical 级别漏洞 |
| `2` | 使用错误、文件不存在或参数无效 |

## 环境变量

### LLM 相关

| 环境变量 | 描述 |
|----------|------|
| `OPENAI_API_KEY` | OpenAI API 密钥 |
| `OPENAI_BASE_URL` | OpenAI 兼容 API 基础 URL |
| `ANTHROPIC_API_KEY` | Anthropic Claude API 密钥 |
| `GOOGLE_API_KEY` | Google Gemini API 密钥 |
| `OLLAMA_BASE_URL` | Ollama 本地服务 URL（默认 `http://localhost:11434`） |
| `GLM_API_KEY` | 智谱 AI / GLM API 密钥 |

### 其他

| 环境变量 | 描述 |
|----------|------|
| `VULE_STATE_FILE` | 默认状态文件路径 |
| `VULE_AUDIT_FILE` | 默认审计日志路径 |
| `VULE_USAGE_FILE` | 默认用量日志路径 |

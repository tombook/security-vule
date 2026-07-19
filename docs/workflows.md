# 典型工作流

本文档介绍 security-vule 的 4 个典型工作流，帮助团队快速上手并建立规范的漏洞管理流程。

---

## 1. Finding 状态工作流

**目标**：建立从漏洞发现到修复关闭的完整生命周期管理。

### 流程概览

```
扫描 → 人工确认 → 修复验证 → 关闭
  │         │           │        │
  ▼         ▼           ▼        ▼
 open   confirmed     fixed    closed
                              (wontfix / false_positive)
```

### 详细步骤

#### 第 1 步：扫描发现漏洞

运行静态扫描，将结果输出到文件：

```bash
security-vule scan ./src --output findings.json
```

此时所有新发现的漏洞状态默认为 `open`。

#### 第 2 步：人工审核确认

安全团队逐个审核漏洞，确认真实存在的标记为 `confirmed`，误报标记为 `false_positive`：

```bash
# 查看所有 open 状态的漏洞
security-vule state list | grep open

# 确认单个漏洞
security-vule state set src/login.php:25:sqli confirmed --note "手动验证确认存在注入"

# 标记为误报
security-vule state set src/utils.php:10:xss false_positive --note "输出已做转义"
```

#### 第 3 步：修复后重新验证

开发修复漏洞后，重新运行扫描验证修复效果：

```bash
# 增量扫描，对比基线
security-vule scan ./src --baseline findings.json --diff --output scan-after-fix.json
```

#### 第 4 步：更新状态为已修复

确认漏洞已修复后，更新状态：

```bash
security-vule state set src/login.php:25:sqli fixed --note "修复于 PR #123"
```

#### 第 5 步：定期清理

定期清理历史数据，保持状态库整洁：

```bash
# 清理 30 天前的已修复条目
security-vule state clean --fixed --older-than 30d

# 清理 90 天前的误报
security-vule state clean --false-positive --older-than 90d
```

### 最佳实践

- **每次 CI 构建自动扫描**：将扫描集成到 CI/CD 流水线
- **基线管理**：主分支维护基线文件，仅关注新增漏洞
- **状态备注**：每次状态变更都添加备注，便于追溯

---

## 2. PoC 验证工作流

**目标**：通过 LLM 生成 + 运行时验证的组合，实现高精度的漏洞确认。

### 流程概览

```
扫描 → generate-poc → 人工审核 → verify-poc → auto-confirm
  │         │            │            │           │
  ▼         ▼            ▼            ▼           ▼
发现漏洞  LLM生成候选   筛选可信PoC  运行时验证  自动标记confirmed
```

### 详细步骤

#### 第 1 步：扫描发现漏洞

```bash
security-vule scan ./src --output findings.json
```

#### 第 2 步：LLM 生成 PoC 候选

使用 LLM 为扫描结果生成 PoC 候选代码：

```bash
security-vule generate-poc findings.json --output poc-candidates.json
```

输出包含每个漏洞的 PoC 候选和生成错误（如有）。

#### 第 3 步：人工审核 PoC 候选

安全团队审核生成的 PoC，筛选出可信的候选：

```bash
# 查看生成结果摘要
cat poc-candidates.json | jq '.count, .errors | length'
```

#### 第 4 步：运行时验证 PoC

启动目标应用（mock 或真实环境），运行 PoC 验证：

```bash
# 启动 mock DVWA 服务（零依赖）
nohup python3 poc-validator/mock_dvwa.py 8080 > /tmp/mock.log 2>&1 &

# 运行 PoC 验证
security-vule verify-poc findings.json --target=mock --output verified.json
```

#### 第 5 步：自动确认已验证漏洞

对于 PoC 验证通过的漏洞，自动将状态更新为 `confirmed`：

```bash
# 方式一：扫描时直接启用 PoC 验证 + 自动确认
security-vule scan ./src --with-poc --poc-target=mock --poc-auto-confirm

# 方式二：事后单独验证后手动批量更新
# （根据 verified.json 结果批量更新状态）
```

### 验证等级说明

| 状态 | 含义 | 置信度 |
|------|------|--------|
| `verified` | PoC 验证成功，漏洞真实存在 | 100% |
| `unverified` | PoC 执行但未成功利用 | 中等 |
| `unconfirmed` | 无法验证（缺少目标环境等） | 低 |

### 最佳实践

- **优先使用 mock 目标**：快速、安全、可重复
- **关键漏洞用真实环境二次验证**：生产前的最终确认
- **保存验证记录**：所有 PoC 验证结果都应归档，用于审计

---

## 3. 用量与成本工作流

**目标**：管理 LLM 用量和成本，确保预算可控。

### 流程概览

```
配置 LLM → 定期查看用量报告 → 设置配额警告 → 优化成本
   │             │                  │             │
   ▼             ▼                  ▼             ▼
 API密钥配置  按维度分组统计   超限告警通知   模型降级/缓存
```

### 详细步骤

#### 第 1 步：配置 LLM 提供商

设置环境变量配置 LLM 访问：

```bash
# 方式一：使用 Ollama 本地模型（推荐，零成本）
export OLLAMA_BASE_URL=http://localhost:11434

# 方式二：使用云服务 API
export OPENAI_API_KEY=sk-xxx
export ANTHROPIC_API_KEY=sk-ant-xxx
export GLM_API_KEY=xxx
```

#### 第 2 步：定期查看用量报告

定期检查 LLM 用量，按不同维度分析：

```bash
# 查看全部用量
security-vule usage report

# 近 30 天按模型分组
security-vule usage report --since=30d --by=model --format=markdown

# 近 7 天按提供商分组
security-vule usage report --since=7d --by=provider

# 按天查看趋势
security-vule usage report --since=30d --by=day
```

#### 第 3 步：设置配额警告

在 CI/CD 或扫描脚本中添加用量检查：

```bash
# 示例：检查本月用量是否超过 $50
MONTHLY_COST=$(security-vule usage report --since=30d --format=json | jq '.total_cost')
if (( $(echo "$MONTHLY_COST > 50" | bc -l) )); then
  echo "警告：本月 LLM 费用已超过 $50"
  # 发送告警...
fi
```

#### 第 4 步：成本优化策略

| 策略 | 说明 | 预期节省 |
|------|------|----------|
| **使用本地模型** | Ollama + Qwen/Llama 本地运行 | 100%（无 API 费用） |
| **模型降级** | 简单任务用小模型，复杂任务用大模型 | 30-70% |
| **结果缓存** | 相同文件复用分析结果 | 视重复率而定 |
| **置信度阈值** | 提高静态分析置信度阈值，减少 LLM 调用 | 20-50% |

### 内置速率限制

security-vule 默认内置以下保护机制，防止意外超支：

| 限制项 | 默认值 | 说明 |
|--------|--------|------|
| 最大 token 数 | 1,000,000 / 扫描 | 防止超大文件消耗过多 |
| 最大费用 | $5.00 / 扫描 | 单次扫描费用上限 |
| 最大 LLM 调用数 | 10,000 / 扫描 | 防止循环调用 |

> 可通过 `LLMAgent` 构造函数自定义这些限制。

### 最佳实践

- **默认关闭 LLM**：仅在需要时启用，避免不必要的费用
- **优先本地模型**：开发环境用 Ollama，生产环境按需使用云服务
- **按月对账**：每月初导出上月用量，与供应商账单核对

---

## 4. 审计与合规工作流

**目标**：建立完整的审计追踪，满足合规要求。

### 流程概览

```
启用审计 → 定期导出 → 验证哈希链完整性 → 归档保存
   │           │             │                  │
   ▼           ▼             ▼                  ▼
记录所有操作  导出审计日志  防篡改验证   长期存储（WORM）
```

### 详细步骤

#### 第 1 步：启用审计日志

security-vule 默认启用审计日志，记录以下操作：

- `scan.started` - 扫描开始
- `scan.completed` - 扫描完成
- `poc.verified` - PoC 验证完成
- 所有 LLM 调用（含 token 用量、费用、耗时）

审计日志采用 JSONL 格式，每条记录包含：

```json
{
  "timestamp": "2026-06-25T10:00:00.000Z",
  "action": "scan.completed",
  "result": "ok",
  "meta": { "findings_count": 10, "files_scanned": 50 },
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

> 每条记录包含前一条记录的哈希，形成哈希链，确保不可篡改。

#### 第 2 步：定期查看审计日志

```bash
# 查看最近 100 条记录
security-vule audit list

# 查看扫描相关操作
security-vule audit list --action=scan.completed

# 查看近 7 天记录
security-vule audit list --since=7d --limit=200
```

#### 第 3 步：定期导出审计日志

按周期导出审计日志，用于归档和合规检查：

```bash
# 导出全部审计日志
security-vule audit export --output audit-export-$(date +%Y%m%d).json
```

#### 第 4 步：验证哈希链完整性

定期验证审计日志的哈希链，确保未被篡改：

```bash
security-vule audit verify
```

输出示例：

```json
{
  "valid": true,
  "total_records": 150,
  "first_record": "2026-06-01T00:00:00.000Z",
  "last_record": "2026-06-25T10:00:00.000Z"
}
```

如果 `valid` 为 `false`，说明审计日志可能被篡改，需要立即调查。

#### 第 5 步：归档保存

将导出的审计日志长期保存，建议：

- **存储介质**：WORM（一次写入多次读取）存储或对象存储开启版本保护
- **保留期限**：根据合规要求（通常 1-7 年）
- **加密**：静态加密 + 传输加密
- **访问控制**：严格限制审计日志的访问权限

### 合规映射

| 合规要求 | security-vule 对应能力 |
|----------|----------------------|
| 操作审计追踪 | 完整的审计日志，记录所有关键操作 |
| 防篡改 | 哈希链机制，确保日志不可篡改 |
| 隐私保护 | 文件内容不记录，仅记录文件哈希和大小 |
| 访问控制 | 审计日志独立存储，权限分离 |

### 最佳实践

- **每周验证哈希链**：定期完整性检查，越早发现问题越好
- **异地备份**：审计日志至少保存在两个独立的存储位置
- **定期审计**：每季度进行一次审计日志审阅，检查异常操作
- **集成 SIEM**：将审计日志转发到 SIEM 系统，进行实时监控和告警

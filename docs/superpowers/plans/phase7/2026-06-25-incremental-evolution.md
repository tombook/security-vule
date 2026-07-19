# Phase 7 · security-vule 增量演进计划(路径 B)

> **基线日期**:2026-06-25
> **基线状态**:702 tests · 697 pass · 5 skip(已含 Phase 5/6 P0 + 10 文件测试覆盖)
> **基线文档**:[`2026-06-24-mssp-platform-redesign-design.md`](../../specs/2026-06-24-mssp-platform-redesign-design.md)(§12 已补全)
> **路径决策**:B — 在现有 scanner 上增量演进,贴近文档精神但不另起 MSSP 平台

## 0. 现状盘点与差距分析

### 0.1 仓库定位

`security-vule` 是**开源 CLI + 库式代码安全扫描器**(非 MSSP SaaS),核心能力:

- **静态扫描**:tree-sitter AST + CPG + DFG + 自研污点分析,支持 PHP/JS/Java/Python/Go/C/C++/Rust
- **F1 指标**:68.5%(4-app benchmark,带 LLM),1 秒扫描速度
- **LLM 增强**(可选):GLM-5.1 / Anthropic / OpenAI / Ollama,17-pattern 密钥脱敏 + prompt injection 防御
- **PoC 运行时验证**:80/80 = 100% precision,mock DVWA + 真实靶场
- **STRIDE 威胁建模**:自动 DFD + STRIDE 映射(`src/threat/`)
- **SARIF 2.1.0**:GitHub Code Scanning / GitLab SAST 原生集成
- **CosmX Galaxy Method**:手动触发的演化循环

### 0.2 与设计文档差距矩阵

| 文档章节 | 文档要求 | 现状 | 差距 | 路径 B 取舍 |
|---|---|---|---|---|
| §4 旅程② 持续白盒扫描 | 主动拉取 + CI/CD + PR 门控 + 静态规则 + SCA(Semgrep/Trivy) | `cli scan` + SARIF + baseline diff + `.github/workflows/` + `.gitlab-ci.d/` | **无 SCA 集成(Semgrep/Trivy)**,`cli scan` 不带 `--watch` 长驻模式 | **增量**:引入 SCA adapter(Semgrep/Trivy,可插拔);`--watch` 暂缓 |
| §5 旅程③ AI PoC 验证 | AI 辅助生成 + 沙箱执行 | `poc-validator/verify_poc.py` + mock/真实靶场 | **CLI 主命令未集成 PoC 验证**,需手动两段式 | **增量**:`cli verify-poc` 命令 + LLM 自动生成 PoC + 集成到 `scan --with-poc` |
| §6 旅程④ 结果处理 | Finding 状态机 + 报告 + 协作 | CLI 输出 JSON/SARIF/Markdown;**无状态流转** | **Finding 无状态机**(open/confirmed/fixed/wontfix/fp) | **增量**:Finding 状态机 + 状态文件格式(.vule-state.json)+ 报告含状态汇总 |
| §7 旅程⑤ 商业运营 | AI token 用量计费 | `src/llm/metrics.ts` + `audit.ts` 有单次 token 计数 | **无聚合账单 / 配额 / 导出** | **增量**:`cli usage report` 命令(时间窗聚合 + JSON/Markdown)+ 配额警告 hook |
| §9 治理 合规 | 审计日志 / RBAC / OWASP/CWE 映射 | LLM 调用审计已有 | **无全局写操作审计**,CLI 无 RBAC;CWE 字段已在 finding 中 | **增量**:全局 audit log(`cli audit --scope=scan/llm/poc`)+ RBAC 暂缓(单用户 CLI 无意义) |
| §10 视觉 | 双门户 Element Plus | 无前端 | — | **不做**(路径 B 排除) |
| §12 页面 | 双门户 21 页 | — | — | **不做**(路径 B 排除) |
| 持续 §4.4 增量扫描 | `--watch` + 增量变更 | `--baseline --diff` 已支持,**但无文件系统 watch** | **增量**:`cli scan --watch` 复用现有 diff 引擎,加 chokidar/fs.watch |

### 0.3 排除项(路径 B 不做)

- ❌ 双门户前端(Element Plus + Vue 3)
- ❌ 多租户 / 客户 / RBAC 鉴权(MSSP 模型)
- ❌ Stripe / 计费支付 / 发票 PDF
- ❌ SSO / SAML / 2FA / 白标
- ❌ 数据库与后端 API(FastAPI/Express)
- ❌ AI PoC 生成阶段的成本配额扣费(仅产出报告)

## 1. 阶段化路线图(6 周,6 批次)

每批次独立 commit / 独立 PR-ready,可单独验收。每批次内子任务按 **子代理驱动**(implementer + spec reviewer + code quality reviewer)。

### Wave 1 · SCA 集成(week 1)

> 对齐文档 §4"持续白盒漏洞挖掘"中 SCA 子项。引入 Semgrep / Trivy 外部扫描器作为可插拔 adapter,与自研 DFG 并行输出,统一归一化格式。

#### 1.1 SCA Adapter 接口(`src/sca/adapter.ts` + types)

- 定义 `SCAAdapter` 接口(`scan(path): Promise<Finding[]>`)
- 统一 Finding schema 与现有 `VulnerabilityFinding` 对齐(severity/cwe/file/line/type/snippet)
- 错误处理:`command not found` / 超时 / 退出码非 0 → 不阻塞主流程,降级为 warning

#### 1.2 Semgrep Adapter(`src/sca/semgrep.ts`)

- 子进程调用 `semgrep --config=auto --json --quiet <path>`
- JSON → `VulnerabilityFinding[]` 转换器
- Semgrep 结果与 DFG 结果去重(同 file:line:type)
- 配置开关:`security-vule.sca.semgrep.enabled=false` 默认关闭(避免外部依赖)

#### 1.3 Trivy Adapter(`src/sca/trivy.ts`)

- 子进程调用 `trivy fs --format json --quiet <path>`(依赖扫描,无 SBOM 时空结果)
- JSON → `VulnerabilityFinding[]` 转换器,severity 映射(critical/high/medium/low/unknown → 现有枚举)
- 同样默认关闭,可选启用

#### 1.4 CLI 集成(`cli scan --sca=semgrep,trivy`)

- 新增 `--sca=<list>` 选项,逗号分隔,启用对应 adapter
- 输出 JSON/SARIF/Markdown 中标注 SCA 来源(`source: 'semgrep' | 'trivy' | 'sv-dfg'`)
- 测试:`tests/unit/sca/semgrep.test.ts`(用 child_process mock)+ `trivy.test.ts` + `integration.test.ts`(真二进制,有 skipIf)

**交付**:CLI 可选启用 SCA;新增 3 文件 + 3 测试文件;现有 702 tests 全绿。

---

### Wave 2 · Finding 状态机(week 2)

> 对齐文档 §6"结果处理与协作"。让 finding 有"打开 / 已确认 / 已修复 / 不修复 / 误报"5 状态,跨扫描增量追踪,基线文件可被工具自身维护。

#### 2.1 Finding 状态定义(`src/state/types.ts`)

- 状态枚举:`open | confirmed | fixed | wontfix | false_positive`
- 状态文件位置:`<scan-target>/.vule-state.json`(默认,可 `--state-file` 覆盖)
- schema:`{ version, updated_at, fingerprints: { [fp]: { status, note, by, at } } }`
- fingerprint 算法复用 SARIF partialFingerprints(`{file}:{line}:{type}`)

#### 2.2 状态管理命令(`src/state/manager.ts` + CLI)

- `cli state list [--state-file]` · 列出所有状态条目
- `cli state set <fingerprint> <status> [--note "..."]` · 修改单个状态
- `cli state clean --fixed --older-than 30d` · 清理 30 天前的已修复记录
- `cli state export/import` · 跨项目迁移(可选)

#### 2.3 `scan` 命令集成状态过滤

- `cli scan --status=open,confirmed`(默认只看 open + confirmed)
- 报告头部新增状态分布:`Open: 12 · Confirmed: 3 · Fixed: 28 · WontFix: 1 · FP: 2`
- SARIF output 中加 `properties.triageState` 字段

#### 2.4 测试 + 文档

- `tests/unit/state/manager.test.ts`(CRUD + fingerprint 一致性 + 并发写保护)
- README 新增"Finding 状态工作流"小节 + 示例

**交付**:状态机独立可测;CLI 4 个新子命令;scan 报告含状态分布;测试 +10 个。

---

### Wave 3 · PoC 验证 CLI 集成(week 3)

> 对齐文档 §5"AI 辅助 PoC 验证"。将 Python `verify_poc.py` 与 `cli scan` 解耦的两段式,合并为一站式 CLI 命令,且与 Wave 2 状态机打通(PoC 已证 → 自动 confirmed)。

#### 3.1 `cli verify-poc <findings.json>` 子命令

- 读取 `cli scan --output` 的 JSON 格式 findings
- 探测 mock/真实靶场可达性(`http://localhost:8080` 健康检查)
- 调用 `poc-validator/verify_poc.py`(Bun.spawn),传 `--target --findings --output`
- 输出合并后的 verified findings(JSON 含 `exploit_proven: true/false`)

#### 3.2 `cli scan --with-poc` 端到端模式

- scan → 自动跑 verify-poc → 合并结果
- 新增 `--poc-target=mock|real|none`(默认 none 保持向后兼容)
- PoC 已证的 finding 在报告中标记 ✅ verified,失败标 ❌ not exploited

#### 3.3 PoC 状态联动

- PoC 已证 → 调用 state manager 自动 `confirmed`(需 `--auto-confirm` 显式开)
- 用法:`cli scan --with-poc --auto-confirm ./src`

#### 3.4 LLM 自动生成 PoC(可选,LLM 模块已有)

- 对未自动验证的 finding,可用 `cli generate-poc <finding-id>` 调 LLM 生成候选 PoC
- 写 `usage_events` 等价物:`src/llm/metrics.ts` 已有 counter
- 输出到 `findings.poc-gen.json`,人工审后入沙箱(此版本仅生成,不入沙箱)

#### 3.5 测试 + 文档

- `tests/unit/cli/verify-poc.test.ts`(Bun.spawn mock + 合并逻辑 + 错误降级)
- `tests/integration/poc-mock.test.ts`(启 mock DVWA,真跑端到端,有 skipIf)
- README "Runtime PoC verification" 章节更新,新增一站式用法

**交付**:`scan --with-poc` 一站式;状态自动 confirmed;LLM 生成 PoC 命令;测试 +5 个。

---

### Wave 4 · 用量计费聚合报告(week 4)

> 对齐文档 §7"商业运营",但路径 B 不做支付,只做"透明化用量报告"。复用 `src/llm/metrics.ts` + `audit.ts`。

#### 4.1 用量事件持久化

- 当前 `metrics.ts` 是内存 counter,改为追加 `.vule-usage.jsonl`(每行一条 event,append-only)
- 事件 schema:`{ ts, capability, provider, model, prompt_tokens, completion_tokens, cost_usd, file_hash, scan_id }`
- 不存文件内容(隐私)

#### 4.2 `cli usage report` 子命令

- `cli usage report --since=30d --by=capability` · 按能力聚合(poc_gen/rca/report/explain)
- `cli usage report --by=project` · 按项目目录聚合(启发式:扫描根目录 basename)
- `cli usage report --by=day --format=markdown` · 每日明细 Markdown 表
- 输出 JSON + Markdown 双格式

#### 4.3 配额警告 hook

- `src/llm/metrics.ts` 增加 threshold 字段(`maxTokens` / `maxCostUsd` / `maxCalls`,默认沿用 RateLimiter)
- 触发时 stderr warning + 退出码 0(警告不阻塞)
- 集成到 `LLMAgent` 构造,可配置

#### 4.4 测试 + 文档

- `tests/unit/usage/persistence.test.ts`(JSONL append + 损坏行跳过 + 大文件分页读取)
- `tests/unit/usage/report.test.ts`(多维度聚合正确性)
- README 新增"AI 用量与成本"小节 + 报告示例

**交付**:用量事件持久化;3 个聚合维度报告;配额警告;测试 +8 个。

---

### Wave 5 · 全局审计日志(week 5)

> 对齐文档 §9"治理与合规"中的"全审计"。当前 LLM 调用有 audit,扫描/PoC/状态变更无,需补齐。

#### 5.1 统一审计层(`src/audit/logger.ts`)

- 接口:`audit(action, target, result, meta?)`
- action 枚举:`scan.started | scan.completed | finding.state_changed | poc.verified | llm.called | api_key.used | config.changed`
- 存储:`<cwd>/.vule/audit.jsonl`(默认)或 `--audit-file` 指定
- schema 包含 `ts / actor / action / target / result / meta / prev_hash`(链式哈希,防篡改基础)
- 自动从 `process.env.USER` 推断 actor

#### 5.2 各模块埋点

- `cli scan`:`scan.started` / `scan.completed`(target=path, result=ok/fail, meta=finding_count)
- `cli state set`:`finding.state_changed`(target=fingerprint, meta=old_status,new_status)
- `cli verify-poc`:`poc.verified`(target=finding_id, result=exploited/safe/failed)
- `src/llm/*`:`llm.called`(已有,统一接口)
- MCP server 调用(MCP 已有 security.ts,加 audit)

#### 5.3 `cli audit` 子命令

- `cli audit list [--action=llm.called] [--since=7d]` · 筛选查询
- `cli audit export --output=audit-export.json` · 导出含哈希链
- `cli audit verify` · 校验哈希链是否被篡改(阶段 3 上 WORM 存储前的前置)

#### 5.4 测试 + 文档

- `tests/unit/audit/logger.test.ts`(append + 哈希链 + 损坏检测)
- `tests/unit/audit/cli-commands.test.ts`(查询 + 导出 + 校验)
- README 新增"审计日志"小节

**交付**:统一 audit 层;CLI 3 个 audit 子命令;哈希链基础;测试 +8 个。

---

### Wave 6 · `--watch` 持续模式 + 体验收尾(week 6)

> 对齐文档 §4.4 增量扫描体验闭环。最后一批,做"开发体验"打磨,无新架构。

#### 6.1 `cli scan --watch <path>`

- 用 `fs.watch`(Node 内置)或 `chokidar`(可选,先尝试内置)
- 监听文件变更(change/add/unlink)
- 触发增量扫描:复用现有 diff 引擎,只扫变更文件
- 终端实时输出 findings + 状态变化
- 支持 Ctrl-C 优雅退出(信号处理)

#### 6.2 报告可视化增强

- Markdown 报告新增 mermaid 状态分布饼图
- 报告头部摘要更紧凑(一行 KPI)

#### 6.3 文档整合

- README 大重构:从 5 段命令流 → 场景化"日常开发 / CI 集成 / 安全审计"
- 新增 `docs/cli-reference.md`(所有子命令 + 选项清单)
- 新增 `docs/workflows.md`(Finding 状态 / PoC 验证 / 用量报告 / 审计 4 个典型工作流)

#### 6.4 测试 + 收尾

- `tests/integration/watch.test.ts`(短时间 watch + 触发 + 退出,skipIf 慢)
- 全量回归:`bun test` 必须 100% pass
- `bun run bench` 性能基线记录

**交付**:`--watch` 体验;文档体系化;全量回归绿。

---

## 2. 优先级与排期

| 批次 | 主题 | 工期 | 文档对齐 | 用户价值 | 建议 |
|---|---|---|---|---|---|
| **Wave 1** | SCA 集成 | 3-4d | §4 SCA | 高(覆盖 SCA 短板,文档明确要求) | ✅ 优先 |
| **Wave 2** | Finding 状态机 | 4-5d | §6 旅程④ | 高(状态流转是协作核心) | ✅ 优先 |
| **Wave 3** | PoC CLI 一站式 | 4-5d | §5 旅程③ | 高(把已有 PoC 能力集成) | ✅ 优先 |
| **Wave 4** | 用量聚合报告 | 2-3d | §7 透明化 | 中(增值,非核心) | 🟡 次 |
| **Wave 5** | 全局审计 | 3-4d | §9 治理 | 中(企业用户重视) | 🟡 次 |
| **Wave 6** | `--watch` + 文档 | 3-4d | §4.4 体验 | 中(开发体验) | 🟢 最后 |

**建议执行顺序**:Wave 1 → 2 → 3 → 4 → 5 → 6,每批独立 commit。

## 3. 执行约定

- **流程**:每批按 **子代理驱动**(`subagent-driven-development`)+ TDD,implementer + spec reviewer + code quality reviewer。
- **测试基线**:每批完成后 `bun test` 必须 ≥ baseline(697 pass + 5 skip),新加测试全绿。
- **Commit 规范**:Conventional Commits,scope 限于 `sca | state | poc | usage | audit | watch | docs`,类型 `feat | fix | docs | test | refactor`。
- **不对外接口兼容**:CLI 子命令、JSON 输出 schema 是 stable;具体字段内部可重构。
- **依赖新增**:Wave 1 可加 `chokidar`(Wave 6);Wave 5 不加依赖;其余不引新外部依赖。

## 4. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| Semgrep / Trivy 不在 CI 环境 | SCA adapter 测试 flakiness | 默认 enabled=false + `skipIf(!hasBinary)` |
| 状态文件 `.vule-state.json` 冲突(并发写入) | 状态丢失 | 文件锁 + 原子重命名 + 冲突警告 |
| PoC 集成依赖 Python + mock 服务 | 跨平台兼容 | spawn 失败降级为 warning,不影响 scan |
| 用量 .vule-usage.jsonl 膨胀 | 磁盘占用 | Wave 4 加 `--rotate-size=10MB` 自动归档 |
| 审计哈希链对性能 | 单次写 ~1ms | 可关 `--no-audit-hash`;异步写缓冲(可选) |

## 5. 不在本计划(明确排除)

- 双门户前端 / RBAC / 多租户(路径 B 整体排除)
- Stripe 支付 / 发票 PDF(路径 B)
- 阶段 3 企业级特性(SSO / 2FA / 白标 / 私有化部署)
- 阶段 2 LLM 深度增强(consensus / 多模型投票 / 解释生成)
- 文档 §10/§12 页面设计的视觉实现
- 重写为 FastAPI + Web 平台的架构迁移

## 6. 验收 Checklist(全部 Wave 完成后)

- [ ] `bun test` ≥ 720 tests,0 fail
- [ ] `bun run bench` 性能不退化(扫描时间 ±10%)
- [ ] CLI 6 个新子命令可用 + `--with-poc` + `--watch`
- [ ] README 重构完成 + 2 个新文档(cli-reference / workflows)
- [ ] 文档 §12 标记的"路径 B 不实现"明确标注(避免后续误以为漏了前端)
- [ ] 单个 commit 可分别回滚(无大爆炸提交)
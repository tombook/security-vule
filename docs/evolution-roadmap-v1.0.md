# security-vule 进化路线图 v1.0 (2026-06-10)

> **Date**: 2026-06-10
> **Current version**: v0.3.0 (29 cosmic-galaxy dimensions, CPG core, dual-model consensus, verify pass)
> **Status**: 8 Sprints completed; foundation laid
> **Next step**: 从 "工具" 进化为 "AI 安全平台"

---

## 0. 进化哲学 (Evolution Philosophy)

> **"Eat your own dog food"** — security-vule 用来扫描别人代码的安全漏洞, 但自己作为 AI 系统, 也必须符合 AI 安全最佳实践。
>
> **三轴并进**: 检测能力 × AI 安全 × 生态贡献, 缺一不可。

未来12 个月的进化将围绕这三条轴展开, **不再是单一维度性能优化**, 而是 **平台化 + 生态化**。

---

## 1. 当前状态快照 (v0.3)

| 维度 | 当前 | 已完成 | 待提升 |
|------|------|--------|--------|
| **静态分析** | 21 漏洞类型 | ✅ tree-sitter + 污点 | SQL 污点规则缺失 |
| **LLM 模式** | 双模型 + verify | ✅ 22 发现/12 文件 | 跨文件分析、Context 循环 |
| **29 维度 UVRS** | cosmic-galaxy 对齐 | ✅ 全部注册 | 数学框架深度 |
| **CPG 核心** | 5 边类型 | ✅ types/builder/queries/metrics | 跨函数污染传播 |
| **CLI/Web UI** | 5 命令 | ✅ D3+Plotly+Bun.serve | 实时协作 |
| **PoC 验证** | 100% 11/11 | ✅ Playwright + curl | 半自动 PoC 生成 |
| **测试套件** | 771/771 | ✅ 87 文件 | Cosmic-galaxy 集成测试 |
| **AI 安全** | 脱敏+注入防护 | ✅ 17+12 模式 | Rate limit + Cost cap |
| **生态贡献** | — | ❌ 空白 | OWASP/ATLAS 提交 |

---

## 2. 进化策略: 4 个 Sprint 周期, 12 个月

### Phase 1: **性能突破** (Month 1-3) — 短期
> 解决 "速度慢、消耗高、缺验证" 三大瓶颈

### Phase 2: **智能跃迁** (Month 4-6) — 中期
> 引入多轮推理、跨文件污染、自我修复

### Phase 3: **产品化** (Month 7-9) — 中长期
> IDE 集成、SaaS 化、协作

### Phase 4: **生态贡献** (Month 10-12) — 长期
> OWASP/ATLAS 标准、开源生态、研究论文

---

## 3. Phase 1: 性能突破 (Month 1-3)

### 🎯 核心 KPI
- 扫描速度: 52s/文件 → **< 10s/文件** (5x 提升)
- Token 成本: 85K/12 文件 → **< 20K/12 文件** (75% 降低)
- 召回: 22/12 → **30+/12** (10 个新增维度发现)
- 误报率: 14% → **< 5%** (二次验证 + 缓存)
- AI 红队基准: 加入 self-test corpus (50 个注入样本)

### Sprint 9: LLM 响应缓存 + 增量扫描

**目标**: 解决 token 成本和扫描速度问题

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| SHA-256 键控的 diskcache | P0 | 1 天 | `src/engine/cache.ts` |
| Git diff 增量扫描 (`security-vule diff`) | P0 | 3 天 | `src/integration/incremental.ts` |
| 基础 baseline 管理 (`vule baseline save/load`) | P0 | 2 天 | `src/integration/baseline.ts` |
| Rate limit + Cost cap ($5/scan) | P0 | 1 天 | `src/detection/llm-agent.ts` |
| 缓存命中统计 + 仪表板 | P1 | 2 天 | `src/visualization/dashboard.ts` |
| **小计** | | **9 天** | |

**实施后预期**:
- 重扫同一文件: **0 token, < 100ms** (缓存命中)
- CI/CD 增量扫描: **200x 提速** (只扫 50 改动的文件 vs 10000 总文件)
- 无限误用防护: 单次扫描 > $5 自动中止

### Sprint 10: AI 红队自测 (Self-Red-Team)

**目标**: security-vule 作为 AI 系统的健壮性

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 创建 `corpus/ai-redteam/prompt-injection-php/` (50 个样本) | P0 | 2 天 | `corpus/` |
| 模型提取测试 (文件名含 API key) | P0 | 1 天 | `tests/redteam/` |
| Hallucination 测试集 (10 个无漏洞文件) | P0 | 1 天 | `corpus/clean/` |
| Chaos engineering (网络断开 / API 限流 / 非法 JSON) | P0 | 3 天 | `tests/chaos/` |
| 注入检测覆盖率报告 | P1 | 1 天 | `docs/ai-redteam-report.md` |
| **小计** | | **8 天** | |

**实施后预期**:
- security-vule 在 50 个注入样本上的检测率 > 95%
- security-vule 在 10 个无漏洞文件上 0 误报 (无幻觉)
- 故障注入下 graceful degradation (不死锁、不崩溃)

### Sprint 11: SQL 污点规则 (AST 增强)

**目标**: 解决 SQL 注入 AST 完全无法检测的盲区 (当前 LLM 是唯一 SQL 检测通道)

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| PHP `mysql_query` / `mysqli_query` / `$pdo->query` 污点规则 | P0 | 3 天 | `src/engine/taint-sql.ts` |
| Python cursor.execute 规则 | P0 | 1 天 | `src/engine/taint-sql-py.ts` |
| JS/TS 模板字符串 SQL 规则 | P1 | 2 天 | `src/engine/taint-sql-js.ts` |
| SQL 注入污点单元测试 (含 OR/UNION/bypass) | P0 | 2 天 | `tests/taint-sql.test.ts` |
| **小计** | | **8 天** | |

**实施后预期**:
- AST 模式独立检出 SQL 注入 (无需 LLM, 5s 速度)
- AST + LLM 共识 = 召回 +5% (双重检测)
- 离线环境 (无 LLM) 也能扫描 SQL 注入

### Sprint 12: 跨文件污点 + 真实 AST 解析器集成

**目标**: 解决单文件粒度 + 真实 parser 集成 (Sprint 5 留下的 stub)

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 真实 `parseSource()` 集成 (替换 Sprint 5 stub) | P0 | 2 天 | `src/integration/commands/analyze.ts` |
| 跨文件 taint propagation (项目级) | P0 | 5 天 | `src/engine/cross-file-taint.ts` |
| 跨文件 require/import 解析 | P0 | 3 天 | `src/engine/module-resolver.ts` |
| 跨文件 PoC 验证 (XSS 跨页面传播) | P1 | 2 天 | `poc-validator/cross-file/` |
| **小计** | | **12 天** | |

**实施后预期**:
- 真实 PHP/Python/JS AST 解析, 不再是按行 stub
- 跨文件 taint 跟踪: 包含 require_once / import / from 链
- 项目级扫描 (从入口文件开始追踪到 sink)

---

## 4. Phase 2: 智能跃迁 (Month 4-6)

### 🎯 核心 KPI
- 召回: 30+/12 → **40+/12** (发现 0day 类漏洞)
- Context 循环: 0 轮 → **3-7 轮** (vulnhuntr 级深度)
- 自我修复建议: 0% → **70%** (LLM 生成 framework-specific fix)
- 跨文件检出: 0 → **3 类型** (storage XSS, IDOR, redirect 链)

### Sprint 13: 多轮推理 + 上下文循环 (vulnhuntr 对齐)

**目标**: 实现 LLM 主动请求其他上下文的能力 (零日漏洞关键)

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 符号解析器 (PHP/Python/JS) | P0 | 5 天 | `src/engine/symbol-resolver.ts` |
| 多轮 loop 控制器 (max 7 rounds) | P0 | 3 天 | `src/detection/multi-round.ts` |
| 三层上下文搜索 (file → project → all_names) | P0 | 2 天 | `src/detection/context-search.ts` |
| 累积上下文管理 (避免重复) | P1 | 2 天 | `src/detection/context-cache.ts` |
| **小计** | | **12 天** | |

**实施后预期**:
- security-vule 可以像 vulnhuntr 一样请求"请显示 $_GET 类的所有方法"
- 深度追踪类/函数/变量的完整符号链
- 检测跨函数的零日漏洞模式

### Sprint 14: 自动 PoC 生成 (LLM-driven)

**目标**: security-vule 自动生成可执行的 PoC (不再只标注漏洞)

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 模板化 PoC 生成器 (HTTP request builder) | P0 | 3 天 | `src/poc/generator.ts` |
| LLM 增强: 根据漏洞类型生成定制 payload | P0 | 3 天 | `src/poc/llm-generator.ts` |
| PoC 执行沙箱 (隔离的 Bun.spawn) | P0 | 2 天 | `src/poc/sandbox.ts` |
| 自动报告: 漏洞 → PoC → 验证 → 报告 | P0 | 2 天 | `src/poc/pipeline.ts` |
| **小计** | | **10 天** | |

**实施后预期**:
- security-vule 发现 SQLi → 自动生成 `' OR '1'='1` → 自动执行 → 截图
- 取代手工编写 PoC
- 客户可以直接用 PoC 报告 + 自动重现演示

### Sprint 15: 自动修复建议 (Framework-Aware)

**目标**: security-vule 自动生成 framework-specific 修复建议

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| Framework 检测 (Flask/Django/Express/Laravel/Symfony) | P0 | 2 天 | `src/detection/framework-detect.ts` |
| Framework-specific remediation 库 (40+ 模式) | P0 | 4 天 | `src/detection/remediation-db.ts` |
| LLM 生成定制 fix (with CWE-89/79/78 templates) | P0 | 3 天 | `src/detection/fix-generator.ts` |
| 修复 diff 输出 (unified diff format) | P0 | 1 天 | `src/detection/diff-formatter.ts` |
| **小计** | | **10 天** | |

**实施后预期**:
- 发现 SQLi → 输出: `use $stmt = $pdo->prepare('SELECT * FROM users WHERE id=:id'); $stmt->execute([':id' => $id]);` (Laravel specific)
- 提供可直接应用的 patch 文件
- 比 Anthropic Harness 的 generic remediation 更 actionable

### Sprint 16: 高级漏洞类型 (存储型 XSS / SSRF / XXE / IDOR)

**目标**: 填补 8 类型 → 15+ 类型 的覆盖差距

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 存储型 XSS 跨页面追踪 (DB → render) | P0 | 4 天 | `src/engine/stored-xss.ts` |
| SSRF 检测 (URL 解析 + 内网 IP 检测) | P0 | 3 天 | `src/engine/ssrf.ts` |
| XXE / XPath 注入 | P1 | 2 天 | `src/engine/xxe.ts` |
| IDOR (基于认证/上下文的访问控制) | P1 | 3 天 | `src/engine/idor.ts` |
| WebSocket / GraphQL 注入 | P2 | 3 天 | `src/engine/ws-graphql.ts` |
| **小计** | | **15 天** | |

**实施后预期**:
- 漏洞类型覆盖: 8 → 15+ (达到 Harness 水平)
- 存储型 XSS 跨页面传播是当前 0% 检出盲区
- SSRF + XXE 补齐 OWASP Top 10

---

## 5. Phase 3: 产品化 (Month 7-9)

### 🎯 核心 KPI
- 主动用户: 0 → **1,000+** (GitHub stars)
- IDE 用户: 0 → **10,000+** (VS Code + JetBrains)
- 集成: 0 → **5 个** (GitHub Action, GitLab, Jenkins, CircleCI, Azure DevOps)

### Sprint 17: VS Code 扩展 + JetBrains Plugin

**目标**: 开发者日常 IDE 体验

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| VS Code 扩展骨架 (TypeScript) | P0 | 5 天 | `extensions/vscode/` |
| 实时扫描 (保存文件时) | P0 | 3 天 | `extensions/vscode/src/extension.ts` |
| 诊断输出 (squiggly underlines) | P0 | 2 天 | `extensions/vscode/src/diagnostics.ts` |
| 修复建议 Quick Fix (lightbulb) | P0 | 2 天 | `extensions/vscode/src/code-actions.ts` |
| JetBrains Plugin 骨架 (Kotlin) | P1 | 5 天 | `extensions/jetbrains/` |
| **小计** | | **17 天** | |

**实施后预期**:
- 开发者保存文件即得到安全反馈
- 修复建议一键应用
- 与 cosmic-galaxy 哲学对齐: "让安全分析像拼写检查一样自然"

### Sprint 18: SaaS 化 (云端扫描)

**目标**: 无需本地安装的云服务

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| REST API 完整化 (`POST /scan`) | P0 | 3 天 | `src/api/server.ts` |
| 用户认证 + 配额 (OAuth + Stripe) | P0 | 5 天 | `src/api/auth.ts` |
| 扫描任务队列 (BullMQ) | P0 | 4 天 | `src/api/queue.ts` |
| Web Dashboard (React + Vite) | P0 | 7 天 | `web/` |
| 多租户隔离 + 计费 | P1 | 4 天 | `src/api/billing.ts` |
| **小计** | | **23 天** | |

**实施后预期**:
- 上传 zip → 10 分钟拿到报告
- 团队协作: 共享扫描结果、趋势分析
- 商业化基础

### Sprint 19: Joern 集成 (生产级 CPG)

**目标**: cosmic-galaxy v8.0 对齐

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| Joern CLI 包装器 (HTTP/CLI 双模式) | P0 | 5 天 | `src/engine/joern-client.ts` |
| Joern CPG → security-vule CPG 转换 | P0 | 4 天 | `src/engine/cpg/joern-bridge.ts` |
| 真实 Java/Kotlin/Go/C 分析 (Joern 原生支持) | P0 | 3 天 | `src/engine/multi-lang.ts` |
| Joern 部署文档 (Docker Compose) | P1 | 1 天 | `deploy/joern/` |
| **小计** | | **13 天** | |

**实施后预期**:
- 完整 cosmic-galaxy v8.0: 支持真实项目的 CPG 生成
- 跨语言: PHP/Python/JS/TS/**Java/Kotlin/Go/C**
- 企业级 Java 项目的安全分析

---

## 6. Phase 4: 生态贡献 (Month 10-12)

### 🎯 核心 KPI
- 论文: 0 → **2 篇** (ICSE/NDSS/USENIX Security 级别)
- 标准: 0 → **3 个** (OWASP AI Security 提交、ATLAS 案例、MITRE 工具)
- 开源社区: 0 → **50+** 贡献者
- 教学: 0 → **3 所大学** 使用 security-vule 作为教学工具

### Sprint 20: OWASP AI Security 贡献

**目标**: 加入 OWASP AI Security & Privacy Guide

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 提交 OWASP AI Exchange (LLM Security 章节) | P0 | 5 天 | `docs/owasp-contribution/` |
| 贡献 `prompts-injection.md` 测试用例 | P0 | 3 天 | `corpus/owasp/` |
| CycloneDX AI-BOM 集成 | P0 | 4 天 | `src/ai-bom/` |
| **小计** | | **12 天** | |

**实施后预期**:
- security-vule 成为 OWASP AI Security & Privacy Guide 官方推荐工具
- 贡献的 50 个注入测试用例被采用
- 行业认可度大幅提升

### Sprint 21: MITRE ATLAS 案例

**目标**: 加入 MITRE ATLAS 数据库

| Task | 优先级 | 估算 | 文件 |
|------|--------|------|------|
| 威胁建模输出映射到 ATLAS 战术 | P0 | 3 天 | `src/atlas/mapper.ts` |
| 5 个 ATLAS 案例研究 (含 PoC) | P0 | 5 天 | `docs/atlas-case-studies/` |
| 提交 MITRE ATLAS 官方仓库 | P0 | 2 天 | `docs/atlas/PR.md` |
| **小计** | | **10 天** | |

**实施后预期**:
- security-vule 作为 ATLAS 工具被收录
- 论文: "Mapping Cosmic Galaxy to ATLAS" (USENIX Security 级别)

### Sprint 22: 研究论文

**目标**: 发表 2 篇学术论文

| 论文 | 会议 | 内容 | 估算 |
|------|------|------|------|
| **Paper 1**: 29 维度 UVRS 多维风险评估 | ICSE 2027 | cosmic-galaxy 框架的应用 | 8 周 |
| **Paper 2**: AI 安全工具自我评估 | NDSS 2027 | security-vule 的 AI red-team 实践 | 8 周 |

| Task | 优先级 | 估算 |
|------|--------|------|
| Paper 1 实验 + 撰写 | P0 | 30 天 |
| Paper 1 提交 + 修订 | P0 | 14 天 |
| Paper 2 实验 + 撰写 | P0 | 30 天 |
| Paper 2 提交 + 修订 | P0 | 14 天 |
| **小计** | | **88 天** |

**实施后预期**:
- security-vule 从 "工具" 升级为 "研究课题"
- 学术界认可的 cosmic-galaxy 实证研究
- 推动行业从单一 LLM 走向多维度评估

---

## 7. 12 个月路线图总结

```
Month:  1  2  3  4  5  6  7  8  9  10 11 12
        ┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
Sprint  9  9  10 11 12 13 14 15 16 17 18 19 20 21 22
        │  │  │  │  │  │  │  │  │  │  │  │  │  │  │
Phase:  1───────  2─────────  3────────  4─────
        性能突破  智能跃迁   产品化     生态
```

| Phase | 时长 | Sprint | 关键产出 |
|-------|------|--------|----------|
| **1. 性能突破** | 3月 | 9-12 | 缓存/增量/SQL 污点/跨文件 |
| **2. 智能跃迁** | 3月 | 13-16 | 多轮推理/自动 PoC/自动修复/高级漏洞 |
| **3. 产品化** | 3月 | 17-19 | IDE/SaaS/Joern |
| **4. 生态贡献** | 3月 | 20-22 | OWASP/ATLAS/论文 |

---

## 8. 关键成功指标 (KPI 总览)

| 指标 | v0.3 (现在) | 3 月后 | 6 月后 | 12 月后 |
|------|:-----------:|:------:|:------:|:-------:|
| **扫描速度** | 52s/文件 | < 10s | < 5s | < 2s |
| **Token 成本** | 85K/12 | < 20K | < 10K | < 5K |
| **召回 (12 文件)** | 22 | 30+ | 40+ | 50+ |
| **误报率** | 14% | < 5% | < 3% | < 2% |
| **漏洞类型覆盖** | 8 | 12 | 16 | 20+ |
| **跨语言** | PHP | PHP+Py+JS+TS | +Java+Go | +Kotlin+C |
| **CI/CD 集成** | GitHub | +GitLab+Jenkins | +5个 | +10个 |
| **GitHub stars** | ~50 | 500+ | 1,000+ | 5,000+ |
| **企业用户** | 0 | 5+ | 20+ | 100+ |
| **OWASP/ATLAS 贡献** | 0 | 0 | 0 | 5+ |
| **论文发表** | 0 | 0 | 0 | 2 |
| **测试套件** | 771 | 1000+ | 1500+ | 3000+ |

---

## 9. 资源与风险

### 9.1 所需资源

| 资源 | 数量 | 说明 |
|------|------|------|
| **全职开发者** | 1-2 人 | 12 个月持续开发 |
| **LLM API 预算** | $200/月 | 测试 + 演示 |
| **服务器** | 1 台 (8 vCPU, 32GB) | Joern + SaaS |
| **会议/差旅** | 2 次 (ICSE + NDSS) | 论文发表 |
| **域名/营销** | $500 | web + 文档 |

### 9.2 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| LLM API 成本失控 | 中 | 中 | Rate limit + cost cap ($5/scan) |
| Joern JVM 依赖 | 中 | 中 | Docker Compose 隔离 |
| 论文被拒 | 高 | 低 | 备选: arXiv 预印本 |
| 竞品 (Harness/OCR) 赶超 | 中 | 中 | 持续创新, 论文护城河 |
| 安全漏洞被发现 | 低 | 高 | 内部 red-team + 公开 CVE 流程 |
| 社区贡献者流失 | 中 | 中 | 文档 + 任务板 + 激励机制 |

---

## 10. 与 cosmic-galaxy 路线图对齐

| cosmic-galaxy 版本 | security-vule 对应 Sprint |
|--------------------|--------------------------|
| **v8.0** (Joern 集成) | Sprint 19 |
| **v9.0** (LLM 集成) | Sprint 13-16 (多轮推理) |
| **v10.0** (SaaS + IDE) | Sprint 17-18 |

> **security-vule 是 cosmic-galaxy 思想在 LLM 时代的具体实现** — cosmic-galaxy 提供数学理论,security-vule 提供工程实践 + 实证验证 + 论文发表。

---

## 11. 立即可执行 (本周)

按 ROI 排序的 5 个 Quick Wins:

1. **LLM 响应缓存** (1 天) → 重复扫描成本 -80%
2. **Cost cap** (半天) → 防止 API 滥用
3. **CI 输出 sanitization** (半天) → 防止 secrets 泄露
4. **AI red-team corpus** (1 天) → 自我防护
5. **真实 parser 集成** (1 天) → 替换 Sprint 5 stub

**总计: 4 天, 立即可执行**

---

## 12. 决策点 (需要用户输入)

1. **商业化路径**: OSS only / SaaS / 企业版三选一
2. **目标用户**: 开发者 / 安全团队 / 企业 CISO
3. **研究 vs 产品**: 优先论文还是优先 IDE 插件
4. **资金来源**: 自我 / 风险投资 / 学术资助

---

## 13. 总结

security-vule 在 v0.3 已建立 29 维度 UVRS 的形式化基础, 8 Sprints 完成了 cosmic-galaxy 思想的 TypeScript 实现。

未来 12 个月的进化目标是 **从"工具"升级为"AI 安全平台"**, 通过:

1. **性能** (5x 提速, 75% 降本)
2. **智能** (多轮推理, 跨文件, 自动 PoC, 自动修复)
3. **产品** (IDE 插件, SaaS, Joern 集成)
4. **生态** (OWASP, ATLAS, 论文)

最终目标: **让 security-vule 成为 AI 时代代码安全分析的事实标准**, 就像 cosmic-galaxy 成为天体物理类比漏洞分析的学术标杆一样。

**本月 (Month 1) 重点**: Sprint 9 性能突破, 立即带来 5x 扫描速度提升 + 75% 成本降低, 为后续所有工作打基础。

> **"以宇宙之理, 护代码安全"** — security-vule v1.0 (2027)
# 分支策略 — security-vule v0.2.0

**确立日期:** 2026-07-05
**决策:** `main` 维持 CLI 扫描器核心 + 已提交的平台基础设施；`test-vuln-review` 作为 phase1-5 完整快照保留为 reference。

## 当前分支拓扑

| 分支 | HEAD | 角色 | 操作 |
|---|---|---|---|
| `main` | `8a9d825` | 当前工作分支：CLI 核心 + state 子系统 + LLM 配额 + monorepo 化 + 平台基础设施（apps/api、apps/web、db、deploy） | active |
| `phase1-mvp-impl` | `5c6f09d` | phase1 MVP 完成（.worktrees/），PoC Bridge payload.matches 反序列化 | worktree-isolated |
| `steadfast-denim` | `7db4e31` | README 重写（.kilo/worktrees/） | archived reference |
| `test-vuln-review` | `5df83ea` | **完整 phase1-5 平台快照**：308 src + 233 tests + 40 UI + 71 prototypes + 28 theory + 3449 测试 / 90%+ 覆盖率 | **archive, do not merge** |
| `tmp-merge-test` | `5c6f09d` | 临时合并实验 | cleanup candidate |

## 为何不 merge test-vuln-review → main

`test-vuln-review` 领先 main **70 commit / 941 文件 / +219,032 行**，自带：

- **独立 UI 栈**：`ui/src/`（React + Tailwind）40 文件，与 main 的 `apps/web`（Vue 3 + Element Plus）形态完全不同
- **独立 API 形态**：phase5 改了 `apps/api` 而 main 的 `apps/api` 是后续独立的 Hono + Drizzle 实现
- **phase5 production engineering**：pino 日志 + Prometheus + OpenTelemetry + Grafana + 3449 测试 / 90.29% 覆盖率
- **prototype / examples / theory**：71 + 51 + 28 个研究/原型文件，不是生产代码

**强行 merge 会：**
1. 引入两套并行的 UI（React vs Vue）
2. 引入与 main 不同的 API 实现路径
3. 把 prototype/theory 文件夹混入生产 monorepo
4. 触发几千行 lockfile/package.json 冲突

## 推荐做法

1. **`test-vuln-review` 保留为 archive**：用于 phase5 思路借鉴（可观测性/性能基线/测试质量），但不直接合并
2. **如需借鉴 phase5 能力**，在 main 上**新开 feat 分支增量实现**，而非 cherry-pick phase5 commit
3. **清理 `tmp-merge-test`**：删除前确认无残留引用
4. **`steadfast-denim`**：如 README 已并入 main，可删除分支

## 工作流

- main: 持续集成 CLI 扫描器核心 + 已 ship 的平台功能（apps/api, apps/web, db, deploy）
- feat/* 分支：单功能 / 单 PR
- phase 推进：在 main 上 feat → PR → 合并，不引入 worktree-isolated 大块
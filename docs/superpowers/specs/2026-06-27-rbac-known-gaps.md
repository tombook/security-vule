# 多租户多用户测试 — 缺陷追踪(已清零)

> 最后更新: 2026-07-04
> 状态: **全部修复,0 个已知缺陷**

## 最终测试结果

| 模块 | 文件 | 用例 | 通过 | 失败 |
|---|---|---:|---:|---:|
| RBAC 矩阵 | rbac_matrix.test.ts | 324 | 324 | **0** |
| 多租户隔离 | multi_tenant_isolation.test.ts | 24 | 24 | **0** |
| RLS 覆盖 | rls_coverage.test.ts | 9 | 9 | **0** |
| 认证会话 | auth.test.ts | 25 | 25 | **0** |
| 用户管理 | user_management.test.ts | 14 | 14 | **0** |
| 双门户边界 | cross_portal_boundary.test.ts | 14 | 14 | **0** |
| 计费隔离 | billing_isolation.test.ts | 11 | 11 | **0** |
| 软删除恢复 | soft_delete_recovery.test.ts | 10 | 10 | **0** |
| API Key/Webhook | api_keys_webhooks.test.ts | 15 | 15 | **0** |
| 审计链 | audit_chain.test.ts | 12 | 12 | **0** |
| **合计** | | **458** | **458 (100%)** | **0** |

## 已修复缺陷(31 项,全部关闭)

### B 类 · API 代码错(6 项)
- B-01: customer.ts exploit_proven 列不存在 -> 移除
- B-02: scans.ts branch NULL -> ?? 'main' 兜底
- B-03: customer reports download 缺失 -> 新增端点
- B-04: auth login 锁定死代码 -> 加 UPDATE + status=locked
- B-05: JWT sub 不校验 -> 加空值检查
- B-06: invite email_verified_at 列不存在 -> 改 last_login_at

### R 类 · RLS 缺失(5 项, migration 0029)
- R-01..05: password_reset_tokens + billing 4 表 customer_isolation policy

### P 类 · RBAC 过松(15 项)
- P-01..13: billing/governance/settings/validation/scans/findings/customers 加 requireRole
- P-20..22: customer settings/members/integrations/notifications 加 requireRole

### 额外修复(5 项)
- disabled/pending 登录拦截
- SE-102 字段名修正
- api-keys projectId 自动查找
- RLS-104 精确化
- customer reports 移除 artifact_sha256

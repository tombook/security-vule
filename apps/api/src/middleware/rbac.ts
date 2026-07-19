// apps/api/src/middleware/rbac.ts
// 通用 RBAC 角色校验 helper(对齐设计 §1.5 + §2.9)
// 用于各路由做角色门控(P-01..P-12 + P-20..P-22)

import type { Context } from 'hono';
import { forbidden } from './error';

export type Role =
  | 'ProviderOwner'
  | 'ProviderAdmin'
  | 'ProviderEngineer'
  | 'ProviderViewer'
  | 'ProviderBilling'
  | 'ProviderAccountMgr'
  | 'ProviderAuditor'
  | 'CustomerAdmin'
  | 'CustomerDeveloper'
  | 'CustomerViewer'
  | 'SystemBot';

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
  tenantId: string;
  portal: 'provider' | 'customer';
  customerId?: string;
}

/** 角色是否在允许集合中 */
export function hasRole(user: AuthUser | undefined, allowed: Role[]): boolean {
  if (!user) return false;
  return allowed.includes(user.role);
}

/**
 * 抛 403;不满足时直接终止请求
 * 用法:requireRole(c, ['ProviderOwner', 'ProviderAdmin'])
 */
export function requireRole(c: Context, allowed: Role[]): AuthUser {
  const user = c.get('user') as AuthUser | undefined;
  if (!user) throw forbidden('Not authenticated');
  if (!hasRole(user, allowed)) {
    throw forbidden(`Role ${user.role} not permitted; required one of: ${allowed.join(', ')}`);
  }
  return user;
}

/** 服务商超管/管理员(常见组合) */
export const PROVIDER_ADMIN_ROLES: Role[] = ['ProviderOwner', 'ProviderAdmin'];

/** 服务商超管/管理员/审计(只读场景) */
export const PROVIDER_READ_ROLES: Role[] = ['ProviderOwner', 'ProviderAdmin', 'ProviderViewer'];

/** 服务商写入角色(不含 Viewer/Auditor/Billing) */
export const PROVIDER_WRITE_ROLES: Role[] = ['ProviderOwner', 'ProviderAdmin', 'ProviderEngineer'];

/** 客户超管 */
export const CUSTOMER_ADMIN_ROLES: Role[] = ['CustomerAdmin'];

/** 客户超管/开发者(可写) */
export const CUSTOMER_WRITE_ROLES: Role[] = ['CustomerAdmin', 'CustomerDeveloper'];

/** 客户任何角色 */
export const CUSTOMER_ANY_ROLES: Role[] = ['CustomerAdmin', 'CustomerDeveloper', 'CustomerViewer'];
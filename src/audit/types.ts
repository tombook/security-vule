/**
 * 审计事件类型定义
 * 基于哈希链的不可篡改审计日志
 */

export const AUDIT_FILENAME = '.vule-audit.jsonl';

export interface AuditEvent {
  /** ISO 时间戳 */
  ts: string;
  /** 操作者 */
  actor: string;
  /** 动作类型 */
  action: string;
  /** 操作目标 */
  target?: string;
  /** 结果 */
  result?: 'ok' | 'fail' | 'warn' | 'skip';
  /** 前一事件的哈希（哈希链） */
  prev_hash?: string;
  /** 当前事件的哈希 */
  hash?: string;
  /** 附加元数据 */
  meta?: Record<string, unknown>;
}

export function isAuditEvent(x: unknown): x is AuditEvent {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const e = x as Record<string, unknown>;
  if (typeof e.ts !== 'string') return false;
  if (typeof e.actor !== 'string') return false;
  if (typeof e.action !== 'string') return false;
  if (e.target !== undefined && typeof e.target !== 'string') return false;
  if (e.result !== undefined && typeof e.result !== 'string') return false;
  if (e.prev_hash !== undefined && typeof e.prev_hash !== 'string') return false;
  if (e.hash !== undefined && typeof e.hash !== 'string') return false;
  if (e.meta !== undefined && (typeof e.meta !== 'object' || Array.isArray(e.meta))) return false;
  return true;
}

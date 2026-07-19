import { openSync, closeSync, writeSync, constants, existsSync, readFileSync, renameSync, unlinkSync, statSync, mkdirSync, appendFileSync, writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { createHash } from 'crypto';
import { type AuditEvent, AUDIT_FILENAME } from './types.js';

export class AuditLockError extends Error {
  constructor(path: string) {
    super(`could not acquire lock for audit file: ${path}`);
    this.name = 'AuditLockError';
  }
}

export interface AuditLoggerOptions {
  filePath?: string;
  actor?: string;
  enableHashChain?: boolean;
  now?: () => Date;
  hashFn?: (data: string) => string;
}

const DEFAULT_LOCK_RETRIES = 10;
const DEFAULT_LOCK_BACKOFF_MS = 20;
const STALE_LOCK_AGE_MS = 30_000;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function lockPath(auditPath: string): string {
  return `${auditPath}.lock`;
}

interface LockPayload {
  pid: number;
  startedAt: number;
}

function parseLockPayload(content: string): LockPayload | null {
  const m = /^(\d+)-(\d+)$/.exec(content.trim());
  if (!m) return null;
  const pid = Number(m[1]);
  const startedAt = Number(m[2]);
  if (!Number.isFinite(pid) || !Number.isFinite(startedAt)) return null;
  return { pid, startedAt };
}

function isPidAlive(pid: number): boolean {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: any) {
    if (e?.code === 'ESRCH') return false;
    if (e?.code === 'EPERM') return true;
    return false;
  }
}

// 默认 SHA-256 哈希函数
function defaultHashFn(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

// 获取默认 actor
function defaultActor(): string {
  return process.env.USER || 'unknown';
}

export class AuditLogger {
  private readonly path: string;
  private readonly actor: string;
  private readonly enableHashChain: boolean;
  private readonly now: () => Date;
  private readonly hashFn: (data: string) => string;
  private readonly lockRetries: number = DEFAULT_LOCK_RETRIES;
  private readonly lockBackoffMs: number = DEFAULT_LOCK_BACKOFF_MS;
  private lockFd: number | null = null;

  constructor(options: AuditLoggerOptions = {}) {
    this.path = options.filePath || join(process.cwd(), AUDIT_FILENAME);
    this.actor = options.actor || defaultActor();
    this.enableHashChain = options.enableHashChain ?? true;
    this.now = options.now || (() => new Date());
    this.hashFn = options.hashFn || defaultHashFn;
  }

  get filePath(): string {
    return this.path;
  }

  // 获取文件锁（参考 state/manager.ts 和 usage/store.ts 的模式）
  async acquireLock(): Promise<void> {
    const lp = lockPath(this.path);
    const dir = dirname(this.path);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const payload: LockPayload = { pid: process.pid, startedAt: this.now().getTime() };
    for (let attempt = 0; attempt < this.lockRetries; attempt++) {
      try {
        this.lockFd = openSync(
          lp,
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
          0o600
        );
        try {
          this.writeLockPayload(this.lockFd, payload);
        } catch {
          try { closeSync(this.lockFd); this.lockFd = null; } catch {}
          try { unlinkSync(lp); } catch {}
          continue;
        }
        return;
      } catch (e: any) {
        if (e?.code !== 'EEXIST') throw e;
        if (this.isLockStale(lp)) {
          try { renameSync(lp, `${lp}.stale-${this.now().getTime()}`); } catch {}
          continue;
        }
        if (attempt === this.lockRetries - 1) throw new AuditLockError(this.path);
        await sleep(this.lockBackoffMs);
      }
    }
    throw new AuditLockError(this.path);
  }

  async releaseLock(): Promise<void> {
    if (this.lockFd != null) {
      try { closeSync(this.lockFd); } catch {}
      this.lockFd = null;
    }
    const lp = lockPath(this.path);
    try { unlinkSync(lp); } catch {}
  }

  private writeLockPayload(fd: number, payload: LockPayload): void {
    writeSync(fd, `${payload.pid}-${payload.startedAt}`);
  }

  private isLockStale(lp: string): boolean {
    let content = '';
    let hasPayload = false;
    try { content = readFileSync(lp, 'utf-8'); hasPayload = true; } catch {}
    if (hasPayload) {
      const payload = parseLockPayload(content);
      if (payload) {
        if (!isPidAlive(payload.pid)) return true;
        const age = this.now().getTime() - payload.startedAt;
        return age > STALE_LOCK_AGE_MS;
      }
    }
    try {
      const age = this.now().getTime() - statSync(lp).mtimeMs;
      return age > STALE_LOCK_AGE_MS;
    } catch {
      return false;
    }
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquireLock();
    try {
      return await fn();
    } finally {
      await this.releaseLock();
    }
  }

  // 计算事件哈希：hash = SHA-256(prev_hash + ts + actor + action + target + result + JSON.stringify(meta))
  private computeEventHash(prevHash: string, event: AuditEvent): string {
    const payload = [
      prevHash,
      event.ts,
      event.actor,
      event.action,
      event.target || '',
      event.result || '',
      JSON.stringify(event.meta || {}),
    ].join('|');
    return this.hashFn(payload);
  }

  // 读取最后一条事件的哈希（用于哈希链接续，考虑并发场景）
  private readLastHash(): string | null {
    if (!existsSync(this.path)) {
      return null;
    }
    const content = readFileSync(this.path, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim().length > 0);
    if (lines.length === 0) {
      return null;
    }
    // 从最后一行往前找，跳过损坏行
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const event = JSON.parse(lines[i]) as AuditEvent;
        if (event.hash) {
          return event.hash;
        }
      } catch {
        continue;
      }
    }
    return null;
  }

  // 记录一条审计事件（异步追加到文件，并发安全）
  async log(
    event: Omit<AuditEvent, 'ts' | 'actor' | 'hash' | 'prev_hash'> & Partial<AuditEvent>
  ): Promise<void> {
    const fullEvent: AuditEvent = {
      ts: event.ts || this.now().toISOString(),
      actor: event.actor || this.actor,
      action: event.action,
      target: event.target,
      result: event.result,
      meta: event.meta,
    };

    await this.withLock(async () => {
      const dir = dirname(this.path);
      if (dir && !existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      if (this.enableHashChain) {
        // 每次加锁后重新读取最后一个 hash，确保并发场景下链的正确性
        const lastHash = this.readLastHash();
        const prevHash = lastHash || '0';
        fullEvent.prev_hash = prevHash;
        fullEvent.hash = this.computeEventHash(prevHash, fullEvent);
      }

      const line = JSON.stringify(fullEvent) + '\n';
      appendFileSync(this.path, line, 'utf-8');
    });
  }

  // 读取所有事件，支持时间范围和 action 过滤；损坏行跳过
  async readAll(options?: { since?: Date; until?: Date; action?: string }): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    if (!existsSync(this.path)) {
      return events;
    }

    const content = readFileSync(this.path, 'utf-8');
    const lines = content.split('\n');
    const since = options?.since?.getTime();
    const until = options?.until?.getTime();
    const actionFilter = options?.action;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const event = JSON.parse(line) as AuditEvent;
        const ts = Date.parse(event.ts);
        if (Number.isNaN(ts)) {
          console.warn(`warning: skipping line ${i + 1} with invalid timestamp in audit file`);
          continue;
        }
        if (since != null && ts < since) continue;
        if (until != null && ts > until) continue;
        if (actionFilter != null && event.action !== actionFilter) continue;
        events.push(event);
      } catch {
        console.warn(`warning: skipping corrupt line ${i + 1} in audit file`);
      }
    }

    return events;
  }

  // 验证哈希链完整性，返回第一个断点的索引或 -1（完整）
  async verifyChain(): Promise<{ valid: boolean; breakIndex: number; total: number }> {
    const events = await this.readAll();
    const total = events.length;

    if (total === 0) {
      return { valid: true, breakIndex: -1, total: 0 };
    }

    let prevHash = '0';
    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      // 如果事件没有 hash 或 prev_hash 字段，视为链断开
      if (!event.hash || !event.prev_hash) {
        return { valid: false, breakIndex: i, total };
      }
      // 验证 prev_hash 是否等于上一个 hash
      if (event.prev_hash !== prevHash) {
        return { valid: false, breakIndex: i, total };
      }
      // 验证当前 hash 是否正确
      const computedHash = this.computeEventHash(prevHash, event);
      if (event.hash !== computedHash) {
        return { valid: false, breakIndex: i, total };
      }
      prevHash = event.hash;
    }

    return { valid: true, breakIndex: -1, total };
  }

  // 导出审计日志（JSONL 格式，每行一个事件，与内部存储格式一致）
  async exportTo(targetPath: string): Promise<number> {
    const events = await this.readAll();
    const dir = dirname(targetPath);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    if (events.length === 0) {
      writeFileSync(targetPath, '', 'utf-8');
      return 0;
    }
    const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
    writeFileSync(targetPath, lines, 'utf-8');
    return events.length;
  }

  // 同步版本的 log（向后兼容）
  logSync(
    event: Omit<AuditEvent, 'ts' | 'actor' | 'hash' | 'prev_hash'> & Partial<AuditEvent>
  ): AuditEvent | null {
    try {
      const fullEvent: AuditEvent = {
        ts: event.ts || this.now().toISOString(),
        actor: event.actor || this.actor,
        action: event.action,
        target: event.target,
        result: event.result,
        meta: event.meta,
      };

      const dir = dirname(this.path);
      if (dir && !existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      if (this.enableHashChain) {
        const lastHash = this.readLastHash();
        const prevHash = lastHash || '0';
        fullEvent.prev_hash = prevHash;
        fullEvent.hash = this.computeEventHash(prevHash, fullEvent);
      }

      const line = JSON.stringify(fullEvent) + '\n';
      appendFileSync(this.path, line, 'utf-8');
      return fullEvent;
    } catch (e) {
      console.warn(`[audit] logSync failed: ${(e as Error).message}`);
      return null;
    }
  }

  // 同步版本的 readAll（向后兼容）
  readAllSync(options?: { since?: Date; until?: Date; action?: string }): AuditEvent[] {
    const events: AuditEvent[] = [];
    if (!existsSync(this.path)) {
      return events;
    }

    const content = readFileSync(this.path, 'utf-8');
    const lines = content.split('\n');
    const since = options?.since?.getTime();
    const until = options?.until?.getTime();
    const actionFilter = options?.action;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const event = JSON.parse(line) as AuditEvent;
        const ts = Date.parse(event.ts);
        if (Number.isNaN(ts)) {
          console.warn(`warning: skipping line ${i + 1} with invalid timestamp in audit file`);
          continue;
        }
        if (since != null && ts < since) continue;
        if (until != null && ts > until) continue;
        if (actionFilter != null && event.action !== actionFilter) continue;
        events.push(event);
      } catch {
        console.warn(`warning: skipping corrupt line ${i + 1} in audit file`);
      }
    }

    return events;
  }

  // 同步版本的 verifyChain（向后兼容）
  verifyChainSync(): { valid: boolean; breakIndex: number; total: number } {
    const events = this.readAllSync();
    const total = events.length;

    if (total === 0) {
      return { valid: true, breakIndex: -1, total: 0 };
    }

    let prevHash = '0';
    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      if (!event.hash || !event.prev_hash) {
        return { valid: false, breakIndex: i, total };
      }
      if (event.prev_hash !== prevHash) {
        return { valid: false, breakIndex: i, total };
      }
      const computedHash = this.computeEventHash(prevHash, event);
      if (event.hash !== computedHash) {
        return { valid: false, breakIndex: i, total };
      }
      prevHash = event.hash;
    }

    return { valid: true, breakIndex: -1, total };
  }

  // 旧版 exportTo（向后兼容，返回 JSON 对象格式）
  exportToSync(targetPath: string): { exported_at: string; total: number; events: AuditEvent[] } {
    const events = this.readAllSync();
    const result = {
      exported_at: this.now().toISOString(),
      total: events.length,
      events,
    };
    const dir = dirname(targetPath);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(targetPath, JSON.stringify(result, null, 2) + '\n');
    return result;
  }
}

// 向后兼容：全局单例
let globalAuditLoggerInstance: AuditLogger | null = null;

export function getGlobalAuditLogger(): AuditLogger {
  if (!globalAuditLoggerInstance) {
    globalAuditLoggerInstance = new AuditLogger();
  }
  return globalAuditLoggerInstance;
}

export function resetGlobalAuditLogger(): void {
  globalAuditLoggerInstance = null;
}

export const GLOBAL_AUDIT_LOGGER = {
  log: (options: Omit<AuditEvent, 'ts' | 'actor' | 'hash' | 'prev_hash'> & Partial<AuditEvent>): AuditEvent | null => {
    try {
      return getGlobalAuditLogger().logSync(options);
    } catch (e) {
      console.warn(`[audit] global log failed: ${(e as Error).message}`);
      return null;
    }
  },
};

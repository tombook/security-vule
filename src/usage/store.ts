import { openSync, closeSync, writeSync, constants, existsSync, readFileSync, renameSync, unlinkSync, statSync, mkdirSync, appendFileSync } from 'fs';
import { dirname, join } from 'path';
import { type UsageEvent, USAGE_FILENAME } from './types.js';

export class UsageLockError extends Error {
  constructor(path: string) {
    super(`could not acquire lock for usage file: ${path}`);
    this.name = 'UsageLockError';
  }
}

export interface UsageStoreOptions {
  lockRetries?: number;
  lockBackoffMs?: number;
  now?: () => Date;
}

const DEFAULT_LOCK_RETRIES = 10;
const DEFAULT_LOCK_BACKOFF_MS = 20;
const STALE_LOCK_AGE_MS = 30_000;
const DEFAULT_MAX_SIZE_BYTES = 10 * 1024 * 1024;
const MAX_ARCHIVES = 3;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function lockPath(usagePath: string): string {
  return `${usagePath}.lock`;
}

function uniqueSuffix(): string {
  return `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
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

export class UsageStore {
  private readonly path: string;
  private readonly lockRetries: number;
  private readonly lockBackoffMs: number;
  private readonly now: () => Date;
  private lockFd: number | null = null;

  constructor(filePath?: string, options: UsageStoreOptions = {}) {
    this.path = filePath || join(process.cwd(), USAGE_FILENAME);
    this.lockRetries = options.lockRetries ?? DEFAULT_LOCK_RETRIES;
    this.lockBackoffMs = options.lockBackoffMs ?? DEFAULT_LOCK_BACKOFF_MS;
    this.now = options.now ?? (() => new Date());
  }

  get filePath(): string {
    return this.path;
  }

  // 获取文件锁（与 state/manager.ts 相同模式）
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
        if (attempt === this.lockRetries - 1) throw new UsageLockError(this.path);
        await sleep(this.lockBackoffMs);
      }
    }
    throw new UsageLockError(this.path);
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

  // 追加一条事件到 JSONL 文件末尾（带文件锁，并发安全）
  async append(event: UsageEvent): Promise<void> {
    const fullEvent: UsageEvent = {
      ...event,
      ts: event.ts || this.now().toISOString(),
    };
    const line = JSON.stringify(fullEvent) + '\n';

    await this.withLock(async () => {
      const dir = dirname(this.path);
      if (dir && !existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      appendFileSync(this.path, line, 'utf-8');
    });
  }

  // 从头读取所有事件，支持时间范围过滤；损坏行跳过并 warn
  async readAll(options?: { since?: Date; until?: Date }): Promise<UsageEvent[]> {
    const events: UsageEvent[] = [];
    if (!existsSync(this.path)) {
      return events;
    }

    const content = readFileSync(this.path, 'utf-8');
    const lines = content.split('\n');
    const since = options?.since?.getTime();
    const until = options?.until?.getTime();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const event = JSON.parse(line) as UsageEvent;
        const ts = Date.parse(event.ts);
        if (Number.isNaN(ts)) {
          console.warn(`warning: skipping line ${i + 1} with invalid timestamp`);
          continue;
        }
        if (since != null && ts < since) continue;
        if (until != null && ts > until) continue;
        events.push(event);
      } catch {
        console.warn(`warning: skipping corrupt line ${i + 1} in usage file`);
      }
    }

    return events;
  }

  // 流式读取，支持过滤器（for await...of）
  async *stream(filter?: (e: UsageEvent) => boolean): AsyncIterable<UsageEvent> {
    if (!existsSync(this.path)) {
      return;
    }

    const content = readFileSync(this.path, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const event = JSON.parse(line) as UsageEvent;
        if (Number.isNaN(Date.parse(event.ts))) {
          console.warn(`warning: skipping line ${i + 1} with invalid timestamp`);
          continue;
        }
        if (!filter || filter(event)) {
          yield event;
        }
      } catch {
        console.warn(`warning: skipping corrupt line ${i + 1} in usage file`);
      }
    }
  }

  // 归档轮换：文件超过 maxSizeBytes 时归档，最多保留 3 个归档，返回归档行数
  async rotate(maxSizeBytes?: number): Promise<number> {
    const maxSize = maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;

    return await this.withLock(async () => {
      if (!existsSync(this.path)) {
        return 0;
      }

      const size = statSync(this.path).size;
      if (size <= maxSize) {
        return 0;
      }

      // 统计归档的行数
      const content = readFileSync(this.path, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim().length > 0);
      const archivedCount = lines.length;

      // 轮转归档文件：从后往前操作
      // .3 -> 删除, .2 -> .3, .1 -> .2
      for (let i = MAX_ARCHIVES; i >= 1; i--) {
        const src = this.archivedPath(i);
        if (!existsSync(src)) continue;
        if (i === MAX_ARCHIVES) {
          unlinkSync(src);
        } else {
          const dst = this.archivedPath(i + 1);
          renameSync(src, dst);
        }
      }

      // 当前文件 -> .1
      renameSync(this.path, this.archivedPath(1));

      return archivedCount;
    });
  }

  private archivedPath(index: number): string {
    const base = this.path.replace(/\.jsonl$/, '');
    return `${base}.${index}.jsonl`;
  }
}

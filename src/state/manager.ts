import { openSync, closeSync, writeSync, constants, existsSync, readFileSync, renameSync, unlinkSync, statSync } from 'fs';
import { dirname } from 'path';
import {
  emptyState,
  fingerprintOf as fpOf,
  isFindingStatus,
  isStateFile,
  STATE_FILE_VERSION,
  defaultAuthor,
  type FindingStateEntry,
  type FindingStatus,
  type FingerprintParts,
  type StateFile,
} from './types.js';

export class StateLockError extends Error {
  constructor(path: string) {
    super(`could not acquire lock for state file: ${path}`);
    this.name = 'StateLockError';
  }
}

export class StateCorruptError extends Error {
  constructor(path: string, cause: unknown) {
    super(`state file is corrupt and was quarantined: ${path}`);
    this.name = 'StateCorruptError';
    this.cause = cause;
  }
}

export interface StateManagerOptions {
  lockRetries?: number;
  lockBackoffMs?: number;
  now?: () => Date;
}

export interface CleanFilter {
  status?: FindingStatus;
  olderThanMs?: number;
}

export interface ImportOptions {
  merge?: boolean;
}

const DEFAULT_LOCK_RETRIES = 5;
const DEFAULT_LOCK_BACKOFF_MS = 50;
const STALE_LOCK_AGE_MS = 30_000;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function lockPath(statePath: string): string {
  return `${statePath}.lock`;
}

function tmpPath(statePath: string): string {
  return `${statePath}.tmp`;
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

export class StateManager {
  private readonly path: string;
  private readonly lockRetries: number;
  private readonly lockBackoffMs: number;
  private readonly now: () => Date;
  private lockFd: number | null = null;
  private corruptRecovery: { quarantinedPath: string; warning: string } | null = null;

  constructor(path: string, options: StateManagerOptions = {}) {
    this.path = path;
    this.lockRetries = options.lockRetries ?? DEFAULT_LOCK_RETRIES;
    this.lockBackoffMs = options.lockBackoffMs ?? DEFAULT_LOCK_BACKOFF_MS;
    this.now = options.now ?? (() => new Date());
  }

  get filePath(): string {
    return this.path;
  }

  get lastCorruptRecovery(): { quarantinedPath: string; warning: string } | null {
    return this.corruptRecovery;
  }

  async acquireLock(): Promise<void> {
    const lp = lockPath(this.path);
    const dir = dirname(this.path);
    if (dir && !existsSync(dir)) {
      const fs = await import('fs');
      fs.mkdirSync(dir, { recursive: true });
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
        if (attempt === this.lockRetries - 1) throw new StateLockError(this.path);
        await sleep(this.lockBackoffMs);
      }
    }
    throw new StateLockError(this.path);
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

  private warnIfUnexpectedMissing(expectedExisted: boolean): boolean {
    if (expectedExisted && !existsSync(this.path)) {
      console.error(`warning: state file disappeared: ${this.path} (refusing to overwrite existing in-memory state)`);
      return true;
    }
    return false;
  }

  async load(): Promise<StateFile> {
    if (!existsSync(this.path)) {
      this.corruptRecovery = null;
      return emptyState();
    }
    let raw: string;
    try {
      raw = readFileSync(this.path, 'utf-8');
    } catch {
      this.corruptRecovery = null;
      return emptyState();
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      const target = this.quarantine(raw);
      if (target) {
        this.corruptRecovery = { quarantinedPath: target, warning: `state file was corrupt, preserved at ${target}` };
        console.error(`warning: ${this.corruptRecovery.warning}`);
      }
      return emptyState();
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      const target = this.quarantine(raw);
      if (target) {
        this.corruptRecovery = { quarantinedPath: target, warning: `state file was corrupt, preserved at ${target}` };
        console.error(`warning: ${this.corruptRecovery.warning}`);
      }
      return emptyState();
    }
    const obj = parsed as Record<string, unknown>;
    const fps = (obj.fingerprints && typeof obj.fingerprints === 'object' && !Array.isArray(obj.fingerprints))
      ? obj.fingerprints as Record<string, unknown>
      : {};
    const cleaned: Record<string, FindingStateEntry> = {};
    for (const [k, v] of Object.entries(fps)) {
      if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
      const e = v as Record<string, unknown>;
      const status = e.status;
      if (!isFindingStatus(status as string)) continue;
      const entry: FindingStateEntry = {
        status,
        by: typeof e.by === 'string' ? e.by : defaultAuthor(),
        at: typeof e.at === 'string' ? e.at : new Date().toISOString(),
      };
      if (typeof e.note === 'string') entry.note = e.note;
      cleaned[k] = entry;
    }
    this.corruptRecovery = null;
    return {
      version: typeof obj.version === 'number' ? obj.version : STATE_FILE_VERSION,
      updated_at: typeof obj.updated_at === 'string' ? obj.updated_at : new Date().toISOString(),
      fingerprints: cleaned,
    };
  }

  private quarantine(_raw: string): string | null {
    const target = `${this.path}.corrupt-${uniqueSuffix()}`;
    try {
      renameSync(this.path, target);
      return target;
    } catch (e) {
      console.error(`error: failed to quarantine corrupt state file: ${(e as Error).message}`);
      return null;
    }
  }

  async save(state: StateFile): Promise<void> {
    await this.withLock(async () => {
      const payload: StateFile = {
        version: state.version || STATE_FILE_VERSION,
        updated_at: this.now().toISOString(),
        fingerprints: state.fingerprints,
      };
      const json = JSON.stringify(payload, null, 2) + '\n';
      const dir = dirname(this.path);
      if (dir && !existsSync(dir)) {
        const fs = await import('fs');
        fs.mkdirSync(dir, { recursive: true });
      }
      const tmp = tmpPath(this.path);
      await Bun.write(tmp, json);
      renameSync(tmp, this.path);
    });
  }

  async getStatus(fp: string): Promise<FindingStatus | undefined> {
    const s = await this.load();
    return s.fingerprints[fp]?.status;
  }

  async getAll(): Promise<Record<string, FindingStateEntry>> {
    const s = await this.load();
    return s.fingerprints;
  }

  async setStatus(
    fp: string,
    status: FindingStatus,
    note?: string,
    by?: string
  ): Promise<void> {
    if (!isFindingStatus(status)) {
      throw new Error(`invalid status: ${status}`);
    }
    await this.withLock(async () => {
      const existed = existsSync(this.path);
      const s = await this.load();
      if (this.warnIfUnexpectedMissing(existed)) return;
      const entry: FindingStateEntry = {
        status,
        by: by || defaultAuthor(),
        at: this.now().toISOString(),
      };
      if (note !== undefined && note !== null && note !== '') entry.note = note;
      s.fingerprints[fp] = entry;
      s.updated_at = entry.at;
      await this.writeUnlocked(s);
    });
  }

  async clean(filter: CleanFilter): Promise<number> {
    return await this.withLock(async () => {
      const existed = existsSync(this.path);
      const s = await this.load();
      if (this.warnIfUnexpectedMissing(existed)) return 0;
      const cutoff = filter.olderThanMs != null
        ? this.now().getTime() - filter.olderThanMs
        : null;
      let removed = 0;
      for (const [fp, entry] of Object.entries(s.fingerprints)) {
        const statusMatch = !filter.status || entry.status === filter.status;
        const ageMatch = cutoff == null
          || (Date.parse(entry.at) <= cutoff);
        if (statusMatch && ageMatch) {
          delete s.fingerprints[fp];
          removed++;
        }
      }
      if (removed > 0) {
        s.updated_at = this.now().toISOString();
        await this.writeUnlocked(s);
      }
      return removed;
    });
  }

  async exportTo(target: string): Promise<void> {
    const s = await this.load();
    const json = JSON.stringify(s, null, 2) + '\n';
    await Bun.write(target, json);
  }

  async importFrom(source: string, options: ImportOptions = {}): Promise<void> {
    const raw = readFileSync(source, 'utf-8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(`import source is not valid JSON: ${source}`);
    }
    const safeParsed: StateFile = isStateFile(parsed)
      ? parsed
      : { version: STATE_FILE_VERSION, updated_at: new Date().toISOString(), fingerprints: {} };
    await this.withLock(async () => {
      const existed = existsSync(this.path);
      const current = await this.load();
      if (this.warnIfUnexpectedMissing(existed)) return;
      const next: StateFile = options.merge
        ? {
            ...current,
            fingerprints: { ...current.fingerprints, ...safeParsed.fingerprints },
          }
        : {
            version: safeParsed.version || STATE_FILE_VERSION,
            updated_at: this.now().toISOString(),
            fingerprints: safeParsed.fingerprints,
          };
      next.updated_at = this.now().toISOString();
      await this.writeUnlocked(next);
    });
  }

  private async writeUnlocked(state: StateFile): Promise<void> {
    const json = JSON.stringify(state, null, 2) + '\n';
    const dir = dirname(this.path);
    if (dir && !existsSync(dir)) {
      const fs = await import('fs');
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmp = tmpPath(this.path);
    await Bun.write(tmp, json);
    renameSync(tmp, this.path);
  }
}

export { fpOf as fingerprintOf };
export type { FindingStateEntry, FindingStatus, StateFile, FingerprintParts };

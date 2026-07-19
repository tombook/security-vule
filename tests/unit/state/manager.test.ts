import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  StateManager,
  StateLockError,
  StateCorruptError,
} from '../../../src/state/manager.js';
import {
  fingerprintOf,
  emptyState,
  isFindingStatus,
  STATE_STATUSES,
} from '../../../src/state/types.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-state-'));
}

describe('state/manager: lifecycle', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('load() returns empty state when file does not exist', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    const s = await mgr.load();
    expect(s.version).toBe(1);
    expect(s.fingerprints).toEqual({});
  });

  test('save() then load() round-trips state', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    await mgr.setStatus('a.py:1:xss', 'confirmed', 'looks real', 'alice');
    const reloaded = new StateManager(path);
    const s = await reloaded.load();
    expect(s.fingerprints['a.py:1:xss'].status).toBe('confirmed');
    expect(s.fingerprints['a.py:1:xss'].by).toBe('alice');
    expect(s.fingerprints['a.py:1:xss'].note).toBe('looks real');
  });

  test('setStatus() writes a file with updated_at refreshed', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    const before = new Date().toISOString();
    await mgr.setStatus('f.py:10:sqli', 'fixed', undefined, 'bob');
    const raw = JSON.parse(readFileSync(path, 'utf-8'));
    expect(raw.version).toBe(1);
    expect(raw.updated_at >= before).toBe(true);
    expect(raw.fingerprints['f.py:10:sqli'].status).toBe('fixed');
    expect(raw.fingerprints['f.py:10:sqli'].by).toBe('bob');
  });

  test('setStatus() updates existing entry (overwrites status + by + at + note)', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'open', 'first', 'alice');
    await mgr.setStatus('a.py:1:xss', 'confirmed', 'second', 'bob');
    const s = await mgr.load();
    const entry = s.fingerprints['a.py:1:xss'];
    expect(entry.status).toBe('confirmed');
    expect(entry.note).toBe('second');
    expect(entry.by).toBe('bob');
  });
});

describe('state/manager: getStatus', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('returns undefined for unknown fingerprint', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    expect(await mgr.getStatus('unknown.py:99:xyz')).toBeUndefined();
  });

  test('returns stored status for known fingerprint', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'wontfix', 'not exploitable', 'alice');
    expect(await mgr.getStatus('a.py:1:xss')).toBe('wontfix');
  });
});

describe('state/manager: getAll', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('returns empty when nothing set', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    const all = await mgr.getAll();
    expect(all).toEqual({});
  });

  test('returns all stored entries', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'confirmed', undefined, 'alice');
    await mgr.setStatus('b.py:2:sqli', 'fixed', undefined, 'bob');
    const all = await mgr.getAll();
    expect(Object.keys(all).sort()).toEqual(['a.py:1:xss', 'b.py:2:sqli']);
    expect(all['a.py:1:xss'].status).toBe('confirmed');
    expect(all['b.py:2:sqli'].status).toBe('fixed');
  });
});

describe('state/manager: fingerprint consistency', () => {
  test('fingerprintOf uses file:line:type format', () => {
    expect(fingerprintOf({ file: 'src/x.py', line: 42, type: 'sqli' }))
      .toBe('src/x.py:42:sqli');
  });
  test('STATE_STATUSES covers exactly 5 expected values', () => {
    expect([...STATE_STATUSES].sort())
      .toEqual(['confirmed', 'false_positive', 'fixed', 'open', 'wontfix']);
  });
  test('isFindingStatus accepts valid statuses and rejects garbage', () => {
    for (const s of STATE_STATUSES) expect(isFindingStatus(s)).toBe(true);
    expect(isFindingStatus('Open')).toBe(false);
    expect(isFindingStatus('verified')).toBe(false);
    expect(isFindingStatus('')).toBe(false);
  });
});

describe('state/manager: clean', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('clean({status: "fixed"}) removes only fixed entries', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'fixed', undefined, 'alice');
    await mgr.setStatus('b.py:2:sqli', 'confirmed', undefined, 'alice');
    await mgr.setStatus('c.py:3:rce', 'wontfix', undefined, 'alice');
    const removed = await mgr.clean({ status: 'fixed' });
    expect(removed).toBe(1);
    const all = await mgr.getAll();
    expect(Object.keys(all).sort()).toEqual(['b.py:2:sqli', 'c.py:3:rce']);
  });

  test('clean({olderThanMs}) removes only entries older than the cutoff', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    const old = new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString();
    const fresh = new Date().toISOString();
    const state = emptyState();
    state.fingerprints['a.py:1:xss'] = { status: 'fixed', by: 'alice', at: old };
    state.fingerprints['b.py:2:sqli'] = { status: 'fixed', by: 'bob', at: fresh };
    await mgr.save(state);
    const cutoff = 1000 * 60 * 60 * 24 * 30;
    const removed = await mgr.clean({ olderThanMs: cutoff });
    expect(removed).toBe(1);
    const all = await mgr.getAll();
    expect(Object.keys(all)).toEqual(['b.py:2:sqli']);
  });

  test('clean with both filters intersects (status AND olderThanMs)', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    const old = new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString();
    const fresh = new Date().toISOString();
    const state = emptyState();
    state.fingerprints['old-fixed'] = { status: 'fixed', by: 'alice', at: old };
    state.fingerprints['old-confirmed'] = { status: 'confirmed', by: 'alice', at: old };
    state.fingerprints['fresh-fixed'] = { status: 'fixed', by: 'alice', at: fresh };
    await mgr.save(state);
    const removed = await mgr.clean({ status: 'fixed', olderThanMs: 1000 * 60 * 60 * 24 * 30 });
    expect(removed).toBe(1);
    const all = await mgr.getAll();
    expect(Object.keys(all).sort()).toEqual(['fresh-fixed', 'old-confirmed']);
  });
});

describe('state/manager: export / import', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('export writes the current state to a JSON file', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'confirmed', 'looks real', 'alice');
    const exportPath = join(dir, 'exported.json');
    await mgr.exportTo(exportPath);
    const raw = JSON.parse(readFileSync(exportPath, 'utf-8'));
    expect(raw.version).toBe(1);
    expect(raw.fingerprints['a.py:1:xss'].status).toBe('confirmed');
  });

  test('import replaces the current state with the imported one', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    await mgr.setStatus('local.py:1:xss', 'confirmed', undefined, 'alice');
    const incoming = {
      version: 1,
      updated_at: new Date().toISOString(),
      fingerprints: {
        'remote.py:2:sqli': { status: 'fixed' as const, by: 'bob', at: new Date().toISOString() },
      },
    };
    const importPath = join(dir, 'incoming.json');
    writeFileSync(importPath, JSON.stringify(incoming));
    await mgr.importFrom(importPath, { merge: false });
    const all = await mgr.getAll();
    expect(Object.keys(all)).toEqual(['remote.py:2:sqli']);
  });

  test('import with merge:true keeps both old and new entries', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('local.py:1:xss', 'confirmed', undefined, 'alice');
    const incoming = {
      version: 1,
      updated_at: new Date().toISOString(),
      fingerprints: {
        'remote.py:2:sqli': { status: 'fixed' as const, by: 'bob', at: new Date().toISOString() },
      },
    };
    const importPath = join(dir, 'incoming.json');
    writeFileSync(importPath, JSON.stringify(incoming));
    await mgr.importFrom(importPath, { merge: true });
    const all = await mgr.getAll();
    expect(Object.keys(all).sort()).toEqual(['local.py:1:xss', 'remote.py:2:sqli']);
  });
});

describe('state/manager: corrupt-file recovery', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('non-JSON content is quarantined as .corrupt-<ts> and a fresh state starts', async () => {
    const path = join(dir, '.vule-state.json');
    writeFileSync(path, '{not valid json');
    const mgr = new StateManager(path);
    const s = await mgr.load();
    expect(s.fingerprints).toEqual({});
    const dirEntries = (await Bun.file(path).parent?.exists()) ? null : null;
    const found = (await import('fs')).readdirSync(dir).filter((n: string) =>
      n.startsWith('.vule-state.json.corrupt-')
    );
    expect(found.length).toBe(1);
    const corrupted = readFileSync(join(dir, found[0]), 'utf-8');
    expect(corrupted).toBe('{not valid json');
  });

  test('a fingerprint whose status is not a known status is dropped silently', async () => {
    const path = join(dir, '.vule-state.json');
    const raw = {
      version: 1,
      updated_at: new Date().toISOString(),
      fingerprints: {
        'good.py:1:xss': { status: 'fixed', by: 'alice', at: new Date().toISOString() },
        'bad.py:2:sqli': { status: 'whatever', by: 'alice', at: new Date().toISOString() },
      },
    };
    writeFileSync(path, JSON.stringify(raw));
    const mgr = new StateManager(path);
    const s = await mgr.load();
    expect(Object.keys(s.fingerprints).sort()).toEqual(['good.py:1:xss']);
  });

  test('non-object root in state file is treated as corrupt and quarantined', async () => {
    const path = join(dir, '.vule-state.json');
    writeFileSync(path, '["not", "an", "object"]');
    const mgr = new StateManager(path);
    const s = await mgr.load();
    expect(s.fingerprints).toEqual({});
    const found = (await import('fs')).readdirSync(dir).filter((n: string) =>
      n.startsWith('.vule-state.json.corrupt-')
    );
    expect(found.length).toBe(1);
  });
});

describe('state/manager: atomic write', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('save() never leaves a .tmp file behind after success', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    await mgr.setStatus('a.py:1:xss', 'confirmed', undefined, 'alice');
    const leftover = (await import('fs')).readdirSync(dir).filter((n: string) =>
      n.endsWith('.tmp')
    );
    expect(leftover).toEqual([]);
  });

  test('save() overwrites an existing state file cleanly', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    await mgr.setStatus('a.py:1:xss', 'confirmed', undefined, 'alice');
    const sizeBefore = readFileSync(path, 'utf-8').length;
    await mgr.setStatus('b.py:2:sqli', 'fixed', undefined, 'bob');
    const reloaded = JSON.parse(readFileSync(path, 'utf-8'));
    expect(reloaded.fingerprints['a.py:1:xss'].status).toBe('confirmed');
    expect(reloaded.fingerprints['b.py:2:sqli'].status).toBe('fixed');
    const sizeAfter = readFileSync(path, 'utf-8').length;
    expect(sizeAfter).toBeGreaterThan(sizeBefore);
  });
});

describe('state/manager: concurrent write protection', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('manual lock release allows next save to proceed', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    await mgr.acquireLock();
    let aborted = false;
    try {
      await mgr.acquireLock();
    } catch (e) {
      aborted = e instanceof StateLockError;
    }
    expect(aborted).toBe(true);
    await mgr.releaseLock();
    await mgr.acquireLock();
    await mgr.releaseLock();
  });

  test('two parallel setStatus calls both succeed; last write wins per fp', async () => {
    const path = join(dir, '.vule-state.json');
    const mgr = new StateManager(path);
    await Promise.all([
      mgr.setStatus('a.py:1:xss', 'confirmed', undefined, 'alice'),
      mgr.setStatus('a.py:1:xss', 'fixed', undefined, 'bob'),
    ]);
    const s = await mgr.load();
    expect(['confirmed', 'fixed']).toContain(s.fingerprints['a.py:1:xss'].status);
  });

  test('two separate manager instances writing different fingerprints in parallel both persist', async () => {
    const path = join(dir, '.vule-state.json');
    const a = new StateManager(path, { lockRetries: 50, lockBackoffMs: 10 });
    const b = new StateManager(path, { lockRetries: 50, lockBackoffMs: 10 });
    await Promise.all([
      a.setStatus('a.py:1:xss', 'confirmed', 'real', 'alice'),
      b.setStatus('b.py:2:sqli', 'fixed', 'patched', 'bob'),
    ]);
    const reloaded = new StateManager(path);
    const s = await reloaded.load();
    expect(s.fingerprints['a.py:1:xss']?.status).toBe('confirmed');
    expect(s.fingerprints['a.py:1:xss']?.by).toBe('alice');
    expect(s.fingerprints['b.py:2:sqli']?.status).toBe('fixed');
    expect(s.fingerprints['b.py:2:sqli']?.by).toBe('bob');
  });

  test('StateLockError thrown when lock cannot be acquired within retries', async () => {
    const path = join(dir, '.vule-state.json');
    const a = new StateManager(path, { lockRetries: 1, lockBackoffMs: 5 });
    const b = new StateManager(path, { lockRetries: 1, lockBackoffMs: 5 });
    await a.acquireLock();
    let err: unknown = null;
    try {
      await b.acquireLock();
    } catch (e) {
      err = e;
    }
    await a.releaseLock();
    expect(err instanceof StateLockError).toBe(true);
  });
});

describe('state/manager: invalid status rejection', () => {
  let dir: string;
  beforeEach(() => {
    dir = freshDir();
  });

  test('setStatus throws on unknown status value', async () => {
    const mgr = new StateManager(join(dir, '.vule-state.json'));
    let err: unknown = null;
    try {
      await mgr.setStatus('a.py:1:xss', 'verified' as any, undefined, 'alice');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
  });
});
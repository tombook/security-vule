import { describe, test, expect, beforeEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  parseStateArgs,
  stateCommand,
  resolveStatePath,
  DEFAULT_STATE_FILENAME,
} from '../../../src/state/cli.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-state-cli-'));
}

describe('state/cli: resolveStatePath', () => {
  test('default path is <target>/.vule-state.json', () => {
    expect(resolveStatePath('/tmp/project', undefined)).toBe(join('/tmp/project', DEFAULT_STATE_FILENAME));
  });
  test('--state-file overrides default', () => {
    expect(resolveStatePath('/tmp/project', '/elsewhere/state.json'))
      .toBe('/elsewhere/state.json');
  });
});

describe('state/cli: parseStateArgs', () => {
  test('parses `state list`', () => {
    const r = parseStateArgs(['list']);
    expect(r.subcommand).toBe('list');
  });
  test('parses `state set <fp> <status>`', () => {
    const r = parseStateArgs(['set', 'a.py:1:xss', 'confirmed']);
    expect(r.subcommand).toBe('set');
    expect(r.fingerprint).toBe('a.py:1:xss');
    expect(r.status).toBe('confirmed');
    expect(r.note).toBeUndefined();
  });
  test('parses `state set <fp> <status> --note "..."`', () => {
    const r = parseStateArgs(['set', 'a.py:1:xss', 'fixed', '--note', 'patched in #42']);
    expect(r.subcommand).toBe('set');
    expect(r.note).toBe('patched in #42');
  });
  test('parses `state clean --fixed`', () => {
    const r = parseStateArgs(['clean', '--fixed']);
    expect(r.subcommand).toBe('clean');
    expect(r.cleanStatus).toBe('fixed');
    expect(r.cleanOlderThanMs).toBeUndefined();
  });
  test('parses `state clean --fixed --older-than 30d`', () => {
    const r = parseStateArgs(['clean', '--fixed', '--older-than', '30d']);
    expect(r.cleanStatus).toBe('fixed');
    expect(r.cleanOlderThanMs).toBe(30 * 24 * 60 * 60 * 1000);
  });
  test('parses `state clean --older-than 7d` (no status)', () => {
    const r = parseStateArgs(['clean', '--older-than', '7d']);
    expect(r.cleanStatus).toBeUndefined();
    expect(r.cleanOlderThanMs).toBe(7 * 24 * 60 * 60 * 1000);
  });
  test('parses `state export --output file.json`', () => {
    const r = parseStateArgs(['export', '--output', 'out.json']);
    expect(r.subcommand).toBe('export');
    expect(r.output).toBe('out.json');
  });
  test('parses `state import --input file.json`', () => {
    const r = parseStateArgs(['import', '--input', 'in.json']);
    expect(r.subcommand).toBe('import');
    expect(r.input).toBe('in.json');
    expect(r.merge).toBe(false);
  });
  test('parses `state import --input file.json --merge`', () => {
    const r = parseStateArgs(['import', '--input', 'in.json', '--merge']);
    expect(r.merge).toBe(true);
  });
  test('returns error when subcommand missing', () => {
    const r = parseStateArgs([]);
    expect('error' in r).toBe(true);
  });
  test('returns error on unknown subcommand', () => {
    const r = parseStateArgs(['reboot']);
    expect('error' in r).toBe(true);
  });
  test('--state-file is captured', () => {
    const r = parseStateArgs(['list', '--state-file', '/tmp/custom.json']);
    expect(r.stateFile).toBe('/tmp/custom.json');
  });
});

describe('state/cli: stateCommand — list', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('empty state prints "no entries" and exits 0', async () => {
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['list'], { target: dir });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.some(c => c.includes('no entries'))).toBe(true);
    expect(existsSync(join(dir, '.vule-state.json'))).toBe(false);
  });

  test('lists all entries with status, by, at, note', async () => {
    const stateFile = join(dir, '.vule-state.json');
    const seed = {
      version: 1,
      updated_at: '2026-06-25T00:00:00.000Z',
      fingerprints: {
        'a.py:1:xss': { status: 'confirmed', by: 'alice', at: '2026-06-25T00:00:00.000Z', note: 'real' },
        'b.py:2:sqli': { status: 'fixed', by: 'bob', at: '2026-06-24T00:00:00.000Z' },
      },
    };
    writeFileSync(stateFile, JSON.stringify(seed));
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['list'], { stateFile });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    const all = captures.join('\n');
    expect(all).toContain('a.py:1:xss');
    expect(all).toContain('confirmed');
    expect(all).toContain('alice');
    expect(all).toContain('b.py:2:sqli');
    expect(all).toContain('fixed');
    expect(all).toContain('bob');
    expect(all).toContain('real');
  });

  test('--state-file overrides default', async () => {
    const custom = join(dir, 'custom.json');
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['list', '--state-file', custom], { target: dir });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.some(c => c.includes('no entries'))).toBe(true);
  });
});

describe('state/cli: stateCommand — set', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('writes a confirmed entry with author from $USER', async () => {
    const origEnv = process.env.USER;
    process.env.USER = 'tester';
    try {
      const stateFile = join(dir, '.vule-state.json');
      const exit = await stateCommand(['set', 'a.py:1:xss', 'confirmed', '--note', 'verified'], { stateFile });
      expect(exit).toBe(0);
      const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
      expect(data.fingerprints['a.py:1:xss'].status).toBe('confirmed');
      expect(data.fingerprints['a.py:1:xss'].by).toBe('tester');
      expect(data.fingerprints['a.py:1:xss'].note).toBe('verified');
    } finally {
      if (origEnv === undefined) delete process.env.USER;
      else process.env.USER = origEnv;
    }
  });

  test('rejects an invalid status with exit code 2', async () => {
    const stateFile = join(dir, '.vule-state.json');
    const exit = await stateCommand(['set', 'a.py:1:xss', 'verified'], { stateFile });
    expect(exit).toBe(2);
  });

  test('rejects missing fingerprint with exit code 2', async () => {
    const exit = await stateCommand(['set'], { stateFile: join(dir, '.vule-state.json') });
    expect(exit).toBe(2);
  });

  test('overwrites an existing entry', async () => {
    const stateFile = join(dir, '.vule-state.json');
    await stateCommand(['set', 'a.py:1:xss', 'open', '--note', 'first'], { stateFile });
    await stateCommand(['set', 'a.py:1:xss', 'confirmed', '--note', 'second'], { stateFile });
    const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(data.fingerprints['a.py:1:xss'].status).toBe('confirmed');
    expect(data.fingerprints['a.py:1:xss'].note).toBe('second');
  });
});

describe('state/cli: stateCommand — clean', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('removes fixed entries and prints count', async () => {
    const stateFile = join(dir, '.vule-state.json');
    const seed = {
      version: 1,
      updated_at: '2026-06-25T00:00:00.000Z',
      fingerprints: {
        'a.py:1:xss': { status: 'fixed', by: 'alice', at: '2026-06-25T00:00:00.000Z' },
        'b.py:2:sqli': { status: 'fixed', by: 'alice', at: '2026-06-25T00:00:00.000Z' },
        'c.py:3:rce': { status: 'confirmed', by: 'alice', at: '2026-06-25T00:00:00.000Z' },
      },
    };
    writeFileSync(stateFile, JSON.stringify(seed));
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['clean', '--fixed'], { stateFile });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.some(c => /removed\s+2/i.test(c))).toBe(true);
    const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(Object.keys(data.fingerprints)).toEqual(['c.py:3:rce']);
  });

  test('clean with no matching entries prints "removed 0"', async () => {
    const stateFile = join(dir, '.vule-state.json');
    const seed = {
      version: 1,
      updated_at: '2026-06-25T00:00:00.000Z',
      fingerprints: {
        'a.py:1:xss': { status: 'open', by: 'alice', at: '2026-06-25T00:00:00.000Z' },
      },
    };
    writeFileSync(stateFile, JSON.stringify(seed));
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['clean', '--fixed'], { stateFile });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.some(c => /removed\s+0/i.test(c))).toBe(true);
  });

  test('clean without --fixed and without --older-than prints usage', async () => {
    const exit = await stateCommand(['clean'], { stateFile: join(dir, '.vule-state.json') });
    expect(exit).toBe(2);
  });

  test('--older-than 30d parses to ~30 days in ms', async () => {
    const stateFile = join(dir, '.vule-state.json');
    const old = new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString();
    const seed = {
      version: 1,
      updated_at: old,
      fingerprints: {
        'a.py:1:xss': { status: 'fixed', by: 'alice', at: old },
        'b.py:2:sqli': { status: 'fixed', by: 'alice', at: new Date().toISOString() },
      },
    };
    writeFileSync(stateFile, JSON.stringify(seed));
    const captures: string[] = [];
    const orig = console.log;
    (console as any).log = (...args: any[]) => { captures.push(args.join(' ')); };
    let exit = -1;
    try {
      exit = await stateCommand(['clean', '--fixed', '--older-than', '30d'], { stateFile });
    } finally {
      (console as any).log = orig;
    }
    expect(exit).toBe(0);
    expect(captures.some(c => /removed\s+1/i.test(c))).toBe(true);
    const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(Object.keys(data.fingerprints)).toEqual(['b.py:2:sqli']);
  });
});

describe('state/cli: stateCommand — export/import', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('export writes a copy to --output', async () => {
    const stateFile = join(dir, '.vule-state.json');
    await stateCommand(['set', 'a.py:1:xss', 'confirmed'], { stateFile });
    const out = join(dir, 'out.json');
    const exit = await stateCommand(['export', '--output', out], { stateFile });
    expect(exit).toBe(0);
    const data = JSON.parse(readFileSync(out, 'utf-8'));
    expect(data.fingerprints['a.py:1:xss'].status).toBe('confirmed');
  });

  test('import replaces state', async () => {
    const stateFile = join(dir, '.vule-state.json');
    await stateCommand(['set', 'a.py:1:xss', 'confirmed'], { stateFile });
    const inp = join(dir, 'in.json');
    const incoming = {
      version: 1,
      updated_at: '2026-06-25T00:00:00.000Z',
      fingerprints: {
        'remote.py:2:sqli': { status: 'fixed', by: 'bob', at: '2026-06-25T00:00:00.000Z' },
      },
    };
    writeFileSync(inp, JSON.stringify(incoming));
    const exit = await stateCommand(['import', '--input', inp], { stateFile });
    expect(exit).toBe(0);
    const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(Object.keys(data.fingerprints)).toEqual(['remote.py:2:sqli']);
  });

  test('import --merge keeps existing entries', async () => {
    const stateFile = join(dir, '.vule-state.json');
    await stateCommand(['set', 'local.py:1:xss', 'confirmed'], { stateFile });
    const inp = join(dir, 'in.json');
    const incoming = {
      version: 1,
      updated_at: '2026-06-25T00:00:00.000Z',
      fingerprints: {
        'remote.py:2:sqli': { status: 'fixed', by: 'bob', at: '2026-06-25T00:00:00.000Z' },
      },
    };
    writeFileSync(inp, JSON.stringify(incoming));
    const exit = await stateCommand(['import', '--input', inp, '--merge'], { stateFile });
    expect(exit).toBe(0);
    const data = JSON.parse(readFileSync(stateFile, 'utf-8'));
    expect(Object.keys(data.fingerprints).sort()).toEqual(['local.py:1:xss', 'remote.py:2:sqli']);
  });
});

describe('state/cli: stateCommand — error paths', () => {
  let dir: string;
  beforeEach(() => { dir = freshDir(); });

  test('missing target returns exit code 2', async () => {
    const exit = await stateCommand(['list']);
    expect(exit).toBe(2);
  });

  test('unknown subcommand returns exit code 2', async () => {
    const exit = await stateCommand(['reboot'], { target: dir });
    expect(exit).toBe(2);
  });
});
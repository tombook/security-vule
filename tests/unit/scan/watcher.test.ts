import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, existsSync, mkdirSync, unlinkSync, renameSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createWatcher, type ScanWatcher } from '../../../src/scan/watcher.js';

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), 'sv-watcher-'));
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('scan/watcher: basic', () => {
  let dir: string;

  beforeEach(() => {
    dir = freshDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('createWatcher 创建成功', () => {
    const watcher = createWatcher({
      root: dir,
      extensions: ['.js', '.ts'],
    });
    expect(watcher).toBeDefined();
    expect(typeof watcher.start).toBe('function');
    expect(typeof watcher.stop).toBe('function');
    expect(typeof watcher.isRunning).toBe('function');
    expect(watcher.isRunning()).toBe(false);
  });

  test('start 后 isRunning 返回 true', async () => {
    const watcher = createWatcher({
      root: dir,
      extensions: ['.js', '.ts'],
    });
    await watcher.start();
    expect(watcher.isRunning()).toBe(true);
    await watcher.stop();
    expect(watcher.isRunning()).toBe(false);
  });

  test('stop 后不再触发回调', async () => {
    let changeCount = 0;
    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 50,
      onChange: () => {
        changeCount++;
      },
    });

    await watcher.start();
    await sleep(100);

    writeFileSync(join(dir, 'test.js'), 'const x = 1;');
    await sleep(200);

    const countAfterFirstWrite = changeCount;
    expect(countAfterFirstWrite).toBeGreaterThan(0);

    await watcher.stop();
    await sleep(100);

    writeFileSync(join(dir, 'test2.js'), 'const y = 2;');
    await sleep(200);

    expect(changeCount).toBe(countAfterFirstWrite);
  });
});

describe('scan/watcher: file events', () => {
  let dir: string;
  let watcher: ScanWatcher;
  let changedFiles: string[][];

  beforeEach(async () => {
    dir = freshDir();
    changedFiles = [];
    watcher = createWatcher({
      root: dir,
      extensions: ['.js', '.ts', '.py'],
      debounceMs: 50,
      onChange: (files) => {
        changedFiles.push(files);
      },
    });
    await watcher.start();
    await sleep(100);
  });

  afterEach(async () => {
    await watcher.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  test('文件变更触发 onChange 回调', async () => {
    const testFile = join(dir, 'test.js');
    writeFileSync(testFile, 'const x = 1;');
    await sleep(200);

    expect(changedFiles.length).toBeGreaterThan(0);
    const lastBatch = changedFiles[changedFiles.length - 1];
    expect(lastBatch.some(f => f.includes('test.js'))).toBe(true);
  });

  test('新增文件触发 onChange', async () => {
    const newFile = join(dir, 'new.ts');
    writeFileSync(newFile, 'export const y = 2;');
    await sleep(200);

    expect(changedFiles.length).toBeGreaterThan(0);
    const lastBatch = changedFiles[changedFiles.length - 1];
    expect(lastBatch.some(f => f.includes('new.ts'))).toBe(true);
  });

  test('删除文件触发 onChange', async () => {
    const testFile = join(dir, 'del.py');
    writeFileSync(testFile, 'x = 1');
    await sleep(200);

    const countAfterCreate = changedFiles.length;

    unlinkSync(testFile);
    await sleep(200);

    expect(changedFiles.length).toBeGreaterThan(countAfterCreate);
  });

  test('子目录中的文件变更也能被检测到', async () => {
    const subDir = join(dir, 'sub');
    mkdirSync(subDir);
    await sleep(50);

    const subFile = join(subDir, 'nested.js');
    writeFileSync(subFile, 'const z = 3;');
    await sleep(200);

    expect(changedFiles.length).toBeGreaterThan(0);
    const lastBatch = changedFiles[changedFiles.length - 1];
    expect(lastBatch.some(f => f.includes('nested.js'))).toBe(true);
  });
});

describe('scan/watcher: debounce', () => {
  let dir: string;

  beforeEach(() => {
    dir = freshDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('debounce 合并多次变更', async () => {
    let callbackCount = 0;
    let totalFiles = 0;

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 100,
      onChange: (files) => {
        callbackCount++;
        totalFiles = files.length;
      },
    });

    await watcher.start();
    await sleep(100);

    writeFileSync(join(dir, 'a.js'), 'const a = 1;');
    await sleep(20);
    writeFileSync(join(dir, 'b.js'), 'const b = 2;');
    await sleep(20);
    writeFileSync(join(dir, 'c.js'), 'const c = 3;');

    await sleep(250);

    expect(callbackCount).toBe(1);
    expect(totalFiles).toBeGreaterThanOrEqual(3);

    await watcher.stop();
  });

  test('同一文件多次变更合并为一次', async () => {
    let callbackCount = 0;
    let lastBatch: string[] = [];

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 100,
      onChange: (files) => {
        callbackCount++;
        lastBatch = files;
      },
    });

    await watcher.start();
    await sleep(100);

    const testFile = join(dir, 'same.js');
    for (let i = 0; i < 5; i++) {
      writeFileSync(testFile, `const x = ${i};`);
      await sleep(20);
    }

    await sleep(250);

    expect(callbackCount).toBe(1);
    expect(lastBatch.filter(f => f.includes('same.js')).length).toBe(1);

    await watcher.stop();
  });
});

describe('scan/watcher: ignoreDirs', () => {
  let dir: string;

  beforeEach(() => {
    dir = freshDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('ignoreDirs 目录下的变更被忽略', async () => {
    let changeCount = 0;

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 50,
      ignoreDirs: ['node_modules', '.git'],
      onChange: () => {
        changeCount++;
      },
    });

    await watcher.start();
    await sleep(100);

    const nmDir = join(dir, 'node_modules');
    mkdirSync(nmDir);
    writeFileSync(join(nmDir, 'dep.js'), 'const x = 1;');
    await sleep(200);

    const countAfterNM = changeCount;

    const gitDir = join(dir, '.git');
    mkdirSync(gitDir);
    writeFileSync(join(gitDir, 'config'), '[core]');
    await sleep(200);

    expect(changeCount).toBe(countAfterNM);

    writeFileSync(join(dir, 'real.js'), 'const y = 2;');
    await sleep(200);

    expect(changeCount).toBeGreaterThan(countAfterNM);

    await watcher.stop();
  });

  test('深层嵌套的忽略目录也能被过滤', async () => {
    let changeCount = 0;

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 50,
      ignoreDirs: ['node_modules'],
      onChange: () => {
        changeCount++;
      },
    });

    await watcher.start();
    await sleep(100);

    const deepNm = join(dir, 'src', 'node_modules');
    mkdirSync(join(dir, 'src'));
    mkdirSync(deepNm);
    writeFileSync(join(deepNm, 'deep.js'), 'const z = 3;');
    await sleep(200);

    const countAfterDeep = changeCount;

    writeFileSync(join(dir, 'src', 'real.js'), 'const w = 4;');
    await sleep(200);

    expect(changeCount).toBeGreaterThan(countAfterDeep);

    await watcher.stop();
  });
});

describe('scan/watcher: extension filter', () => {
  let dir: string;

  beforeEach(() => {
    dir = freshDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('扩展名过滤正确', async () => {
    let changedFiles: string[] = [];

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js', '.ts'],
      debounceMs: 50,
      onChange: (files) => {
        changedFiles = changedFiles.concat(files);
      },
    });

    await watcher.start();
    await sleep(100);

    writeFileSync(join(dir, 'test.js'), 'const x = 1;');
    writeFileSync(join(dir, 'test.ts'), 'const y = 2;');
    writeFileSync(join(dir, 'test.txt'), 'hello');
    writeFileSync(join(dir, 'test.py'), 'x = 1');
    writeFileSync(join(dir, 'test.md'), '# title');

    await sleep(200);

    const jsFiles = changedFiles.filter(f => f.endsWith('.js'));
    const tsFiles = changedFiles.filter(f => f.endsWith('.ts'));
    const txtFiles = changedFiles.filter(f => f.endsWith('.txt'));
    const pyFiles = changedFiles.filter(f => f.endsWith('.py'));
    const mdFiles = changedFiles.filter(f => f.endsWith('.md'));

    expect(jsFiles.length).toBeGreaterThan(0);
    expect(tsFiles.length).toBeGreaterThan(0);
    expect(txtFiles.length).toBe(0);
    expect(pyFiles.length).toBe(0);
    expect(mdFiles.length).toBe(0);

    await watcher.stop();
  });

  test('扩展名大小写不敏感', async () => {
    let changedFiles: string[] = [];

    const watcher = createWatcher({
      root: dir,
      extensions: ['.js'],
      debounceMs: 50,
      onChange: (files) => {
        changedFiles = changedFiles.concat(files);
      },
    });

    await watcher.start();
    await sleep(100);

    writeFileSync(join(dir, 'upper.JS'), 'const x = 1;');
    writeFileSync(join(dir, 'lower.js'), 'const y = 2;');

    await sleep(200);

    expect(changedFiles.filter(f => f.endsWith('.JS') || f.endsWith('.js')).length).toBeGreaterThanOrEqual(2);

    await watcher.stop();
  });
});

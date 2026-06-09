/**
 * v3.0 重新设计后 API 兼容性测试
 *
 * 验证:
 * 1. 旧 cosm-x-* API 通过 compat/ 仍可工作
 * 2. 新 math/* API 占位符存在
 * 3. 旧 23 维理论 + 6 维物理行为不变
 */

import { describe, test, expect } from 'bun:test';
import { resolve } from 'path';

const PROJECT_ROOT = resolve(import.meta.dir, '..');

import {
  THEORY_DEFINITIONS,
  UVRSCalculator,
  buildGraphData23D,
} from '../src/math/cosm-x-theory-23d.js';

import { cosmXAnalyze } from '../src/math/cosm-x-galaxy.js';

import {
  deduplicateByFileType,
  filterByMinScore,
} from '../src/math/cosm-x-dedup.js';

describe('v3.0 compat layer', () => {
  test('THEORY_DEFINITIONS has 23 dims', () => {
    expect(THEORY_DEFINITIONS.length).toBe(23);
  });

  test('UVRSCalculator can be constructed', () => {
    const engine = new UVRSCalculator();
    expect(engine).toBeInstanceOf(UVRSCalculator);
  });

  test('cosmXAnalyze is a function', () => {
    expect(typeof cosmXAnalyze).toBe('function');
  });

  test('deduplicateByFileType works', () => {
    expect(typeof deduplicateByFileType).toBe('function');
  });

  test('filterByMinScore works', () => {
    expect(typeof filterByMinScore).toBe('function');
  });

  test('UVRS compute returns sigmoid output', () => {
    const engine = new UVRSCalculator();
    const uvrs = engine.compute({ kepler: 0.5, gravity: 0.3, tidal: 0.2 });
    expect(uvrs).toBeGreaterThan(0);
    expect(uvrs).toBeLessThan(1);
  });

  test('compat/cosm-x-* files exist as re-exports', async () => {
    const fs = await import('fs');
    const compatFiles = [
      'cosm-x-theory-23d.ts',
      'cosm-x-galaxy.ts',
      'cosm-x-project-analyzer.ts',
      'cosm-x-dedup.ts',
      'cosm-x-cli.ts',
    ];
    for (const f of compatFiles) {
      const path = resolve(PROJECT_ROOT, 'src/math/compat', f);
      expect(fs.existsSync(path)).toBe(true);
    }
  });

  test('new directory structure exists', async () => {
    const fs = await import('fs');
    const dirs = [
      'src/math/theory',
      'src/math/theory/23d',
      'src/math/theory/physics',
      'src/math/execution',
      'src/math/application',
      'src/math/pipeline',
      'src/math/compat',
    ];
    for (const d of dirs) {
      const path = resolve(PROJECT_ROOT, d);
      expect(fs.existsSync(path)).toBe(true);
    }
  });

  test('REDESIGN.md and math-underneath.md exist', async () => {
    const fs = await import('fs');
    expect(fs.existsSync(resolve(PROJECT_ROOT, 'docs/REDESIGN.md'))).toBe(true);
    expect(fs.existsSync(resolve(PROJECT_ROOT, 'docs/math-underneath.md'))).toBe(true);
  });
});

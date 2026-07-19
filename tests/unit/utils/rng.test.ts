import { describe, test, expect } from 'bun:test';
import {
  createRng,
  rngInt,
  rngBool,
  rngUniform,
  rngChoice,
  createIdGen,
  type Rng,
} from '../../../src/utils/rng.js';

describe('rng: createRng', () => {
  test('returns a function', () => {
    const rng = createRng(42);
    expect(typeof rng).toBe('function');
  });

  test('returns floats in [0, 1)', () => {
    const rng = createRng(42);
    for (let i = 0; i < 100; i++) {
      const n = rng();
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(1);
    }
  });

  test('same seed produces same sequence', () => {
    const a = createRng(123);
    const b = createRng(123);
    for (let i = 0; i < 20; i++) {
      expect(a()).toBe(b());
    }
  });

  test('different seeds produce different sequences', () => {
    const a = createRng(1);
    const b = createRng(2);
    let different = 0;
    for (let i = 0; i < 10; i++) {
      if (a() !== b()) different++;
    }
    expect(different).toBeGreaterThan(0);
  });

  test('handles seed=0', () => {
    const rng = createRng(0);
    expect(rng()).toBeGreaterThanOrEqual(0);
  });

  test('handles negative seed', () => {
    const rng = createRng(-42);
    const n = rng();
    expect(n).toBeGreaterThanOrEqual(0);
    expect(n).toBeLessThan(1);
  });
});

describe('rng: rngInt', () => {
  test('produces integers in [0, max)', () => {
    const rng = createRng(42);
    for (let i = 0; i < 100; i++) {
      const n = rngInt(rng, 10);
      expect(Number.isInteger(n)).toBe(true);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(10);
    }
  });

  test('max=0 returns 0', () => {
    const rng = createRng(1);
    expect(rngInt(rng, 0)).toBe(0);
  });

  test('max=1 returns 0', () => {
    const rng = createRng(1);
    expect(rngInt(rng, 1)).toBe(0);
  });
});

describe('rng: rngBool', () => {
  test('returns boolean', () => {
    const rng = createRng(1);
    for (let i = 0; i < 20; i++) {
      const b = rngBool(rng, 0.5);
      expect(typeof b).toBe('boolean');
    }
  });

  test('p=0 always false', () => {
    const rng = createRng(1);
    for (let i = 0; i < 50; i++) {
      expect(rngBool(rng, 0)).toBe(false);
    }
  });

  test('p=1 always true', () => {
    const rng = createRng(1);
    for (let i = 0; i < 50; i++) {
      expect(rngBool(rng, 1)).toBe(true);
    }
  });
});

describe('rng: rngUniform', () => {
  test('produces floats in [lo, hi)', () => {
    const rng = createRng(1);
    for (let i = 0; i < 50; i++) {
      const n = rngUniform(rng, 0, 1);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(1);
    }
  });

  test('handles negative range', () => {
    const rng = createRng(2);
    for (let i = 0; i < 50; i++) {
      const n = rngUniform(rng, -1, 1);
      expect(n).toBeGreaterThanOrEqual(-1);
      expect(n).toBeLessThan(1);
    }
  });

  test('lo == hi returns lo', () => {
    const rng = createRng(3);
    expect(rngUniform(rng, 5, 5)).toBe(5);
  });
});

describe('rng: rngChoice', () => {
  test('picks element from array', () => {
    const rng = createRng(1);
    const arr = ['a', 'b', 'c'];
    for (let i = 0; i < 30; i++) {
      const choice = rngChoice(rng, arr);
      expect(arr).toContain(choice);
    }
  });

  test('single-element array', () => {
    const rng = createRng(1);
    expect(rngChoice(rng, ['only'])).toBe('only');
  });
});

describe('rng: createIdGen', () => {
  test('generates unique ids', () => {
    const idGen = createIdGen('test');
    const a = idGen();
    const b = idGen();
    const c = idGen();
    expect(a).not.toBe(b);
    expect(b).not.toBe(c);
    expect(a).not.toBe(c);
  });

  test('id contains prefix', () => {
    const idGen = createIdGen('abc');
    const id = idGen();
    expect(id).toContain('abc');
  });

  test('default prefix is "id"', () => {
    const idGen = createIdGen();
    const id = idGen();
    expect(id).toContain('id_');
  });

  test('id is unique across many calls', () => {
    const idGen = createIdGen('x');
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(idGen());
    }
    expect(ids.size).toBe(1000);
  });
});

describe('rng: distribution properties', () => {
  test('rngInt distribution is roughly uniform', () => {
    const rng = createRng(7);
    const counts = [0, 0, 0, 0, 0];
    const n = 5000;
    for (let i = 0; i < n; i++) {
      counts[rngInt(rng, 5)]++;
    }
    const expected = n / 5;
    for (const c of counts) {
      expect(Math.abs(c - expected) / expected).toBeLessThan(0.2);
    }
  });

  test('rngBool distribution is roughly balanced at p=0.5', () => {
    const rng = createRng(8);
    let trues = 0;
    const n = 5000;
    for (let i = 0; i < n; i++) {
      if (rngBool(rng, 0.5)) trues++;
    }
    const ratio = trues / n;
    expect(ratio).toBeGreaterThan(0.4);
    expect(ratio).toBeLessThan(0.6);
  });
});

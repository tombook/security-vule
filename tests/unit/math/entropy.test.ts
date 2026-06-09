import { describe, expect, test } from 'bun:test';
import {
  entropy,
  functionEntropy,
  callGraphEntropy,
  tokenEntropy,
  normalizedEntropy,
  jointEntropy,
  conditionalEntropy
} from '../../../src/math/entropy';

describe('entropy', () => {
  test('calculates Shannon entropy for uniform distribution', () => {
    // For a fair coin (p=0.5, p=0.5): H = -0.5*log2(0.5) - 0.5*log2(0.5) = 1
    const result = entropy(['H', 'T']);
    expect(result.value).toBeCloseTo(1, 5);
  });

  test('calculates entropy for biased distribution', () => {
    // For p=[0.9, 0.1]: H = -0.9*log2(0.9) - 0.1*log2(0.1)
    const result = entropy(['a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'b']);
    expect(result.value).toBeGreaterThan(0);
    expect(result.value).toBeLessThan(1);
  });

  test('entropy of single value is 0', () => {
    const result = entropy(['same', 'same', 'same']);
    expect(result.value).toBeCloseTo(0, 5);
  });

  test('function entropy calculates complexity spread', () => {
    const metrics = [
      { complexity: 1, loc: 10, args: 2 },
      { complexity: 5, loc: 50, args: 3 },
      { complexity: 10, loc: 100, args: 1 }
    ];
    const result = functionEntropy(metrics);
    expect(result).toBeGreaterThan(0);
  });

  test('call graph entropy works', () => {
    const outgoingEdges = new Map<string, string[]>([
      ['A', ['B', 'C']],
      ['B', ['C']],
      ['C', []]
    ]);
    const result = callGraphEntropy(outgoingEdges);
    expect(result).toBeGreaterThanOrEqual(0);
  });

  test('token entropy processes string tokens', () => {
    const tokens = ['if', 'else', 'if', 'return', 'return'];
    const result = tokenEntropy(tokens);
    expect(result.value).toBeGreaterThan(0);
    expect(result.distribution.get('if')).toBe(0.4);
  });

  test('normalized entropy scales 0 to 1', () => {
    const uniform = ['a', 'b', 'c', 'd'];
    const result = normalizedEntropy(uniform);
    expect(result).toBeCloseTo(1, 2);
  });

  test('joint entropy of independent events', () => {
    const pairs: [string, string][] = [['a', 'x'], ['b', 'y'], ['c', 'z']];
    const result = jointEntropy(pairs);
    expect(result).toBeGreaterThan(0);
  });

  test('conditional entropy with known distribution', () => {
    const pairs: [string, string][] = [['a', 'x'], ['a', 'x'], ['b', 'y']];
    const xDist = new Map<string, number>([['a', 0.66], ['b', 0.33]]);
    const result = conditionalEntropy(pairs, xDist);
    expect(result).toBeGreaterThanOrEqual(0);
  });
});
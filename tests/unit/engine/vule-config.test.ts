import { describe, expect, test } from 'bun:test';
import { loadConfig, defaultConfig, VuleConfig } from '../../../src/engine/vule-config.js';

describe('VuleConfig', () => {
  test('defaultConfig has all required fields', () => {
    const c = defaultConfig();
    expect(c.weights).toBeDefined();
    expect(c.weights.taint).toBe(0.20);
    expect(c.thresholds.CRITICAL).toBe(0.85);
    expect(c.dimensions.enabled).toContain('ast');
  });

  test('loadConfig parses YAML string', () => {
    const yaml = `
weights:
  taint: 0.5
  ast: 0.5
thresholds:
  LOW: 0.3
  MEDIUM: 0.5
  HIGH: 0.7
  CRITICAL: 0.9
`;
    const c = loadConfig(yaml);
    expect(c.weights.taint).toBe(0.5);
    expect(c.thresholds.CRITICAL).toBe(0.9);
  });

  test('loadConfig accepts flat YAML (no uvrs: wrapper)', () => {
    const yaml = `
weights:
  taint: 0.7
thresholds:
  LOW: 0.1
  MEDIUM: 0.2
  HIGH: 0.3
  CRITICAL: 0.4
`;
    const c = loadConfig(yaml);
    expect(c.weights.taint).toBe(0.7);
    expect(c.thresholds.CRITICAL).toBe(0.4);
  });

  test('loadConfig accepts object input', () => {
    const c = loadConfig({ llm: { provider: 'zhipu' } });
    expect(c.llm.provider).toBe('zhipu');
  });

  test('loadConfig merges with defaults (partial overrides)', () => {
    const yaml = `weights:\n  taint: 0.99\n`;
    const c = loadConfig(yaml);
    expect(c.weights.taint).toBe(0.99);
    expect(c.weights.ast).toBe(0.15); // default preserved
  });

  test('loadConfig loads from file path', async () => {
    const path = '/tmp/vule-test-config.yaml';
    await Bun.write(path, 'weights:\n  taint: 0.42\n');
    const c = loadConfig(path);
    expect(c.weights.taint).toBe(0.42);
    await Bun.write(path, ''); // cleanup
  });
});
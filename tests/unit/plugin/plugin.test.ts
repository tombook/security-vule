import { describe, it, expect } from 'bun:test';
import { PluginRegistry } from '../../../src/plugin/registry.js';
import { PluginPipeline } from '../../../src/plugin/pipeline.js';
import { registerBuiltins, PatternProbe, StatisticalProbe, EnsembleDetector } from '../../../src/plugin/index.js';

describe('Plugin Registry', () => {
  it('registers and loads a plugin', async () => {
    const registry = new PluginRegistry();
    const probe = new PatternProbe();
    registry.register(probe.meta, () => new PatternProbe());

    expect(registry.has('probe.pattern')).toBe(true);
    expect(registry.size).toBe(1);

    const loaded = await registry.load('probe.pattern');
    expect(loaded.state).toBe('ready');
    expect(loaded.meta.id).toBe('probe.pattern');
  });

  it('prevents duplicate registration', () => {
    const registry = new PluginRegistry();
    const probe = new PatternProbe();
    registry.register(probe.meta, () => new PatternProbe());
    expect(() => registry.register(probe.meta, () => new PatternProbe())).toThrow();
  });

  it('unregisters a plugin', async () => {
    const registry = new PluginRegistry();
    const probe = new PatternProbe();
    registry.register(probe.meta, () => new PatternProbe());
    await registry.load('probe.pattern');

    registry.unregister('probe.pattern');
    expect(registry.has('probe.pattern')).toBe(false);
  });

  it('filters by phase', () => {
    const registry = new PluginRegistry();
    registerBuiltins(registry);

    const probes = registry.getByPhase('probe');
    const detectors = registry.getByPhase('detector');

    expect(probes.length).toBeGreaterThanOrEqual(2);
    expect(detectors.length).toBeGreaterThanOrEqual(1);
    expect(probes.every(p => p.phase === 'probe')).toBe(true);
  });

  it('filters by tag', () => {
    const registry = new PluginRegistry();
    registerBuiltins(registry);

    const sqli = registry.getByTag('sqli');
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Built-in Plugins', () => {
  it('PatternProbe detects hardcoded credentials', async () => {
    const probe = new PatternProbe();
    await probe.init();

    const findings = await probe.execute({
      code: 'const API_KEY = "sk-proj-abc123";',
      config: {},
      sharedData: new Map(),
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'AUTH-002')).toBe(true);

    await probe.destroy();
    expect(probe.state).toBe('uninitialized');
  });

  it('StatisticalProbe detects complex code', async () => {
    const probe = new StatisticalProbe();
    await probe.init();

    const complexCode = Array(50).fill('if (x) { for (let i = 0; i < n; i++) { while (true) { switch(v) { case 1: break; } } } }').join('\n');
    const findings = await probe.execute({
      code: complexCode,
      config: {},
      sharedData: new Map(),
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('STAT-001');
  });

  it('StatisticalProbe returns empty for simple code', async () => {
    const probe = new StatisticalProbe();
    await probe.init();

    const findings = await probe.execute({
      code: 'function add(a, b) { return a + b; }',
      config: {},
      sharedData: new Map(),
    });

    expect(findings.length).toBe(0);
  });

  it('EnsembleDetector aggregates findings', async () => {
    const detector = new EnsembleDetector();
    await detector.init();

    const detections = await detector.execute({
      findings: [
        { source: 'probe.pattern', ruleId: 'INJ-001', name: 'SQL Injection', message: 'SQLi detected', confidence: 0.9, severity: 'critical' as const, metadata: {} },
        { source: 'probe.statistical', ruleId: 'INJ-001', name: 'SQL Injection', message: 'Complex code', confidence: 0.7, severity: 'high' as const, metadata: {} },
      ],
      code: 'db.query("SELECT " + input)',
      config: {},
    });

    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].scores).toBeDefined();
    expect(detections[0].confidence).toBeGreaterThan(0);
  });
});

describe('Plugin Pipeline', () => {
  it('runs probe → detector pipeline end-to-end', async () => {
    const registry = new PluginRegistry();
    registerBuiltins(registry);
    await registry.loadAll();

    const pipeline = new PluginPipeline(registry);
    const result = await pipeline.run(
      'const password = "hardcoded_secret"; const token = "abc123";',
      'test.js',
      { minConfidence: 0.1 },
    );

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.timing.total).toBeGreaterThanOrEqual(0);

    await registry.unloadAll();
  });
});

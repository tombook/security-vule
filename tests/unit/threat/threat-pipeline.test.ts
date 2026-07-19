import { describe, test, expect, beforeEach, afterAll } from 'bun:test';
import { ThreatModelPipeline } from '../../../src/threat/threat-pipeline.js';
import { PluginRegistry } from '../../../src/plugin/registry.js';
import { PluginPipeline } from '../../../src/plugin/pipeline.js';
import { generateThreatModel } from '../../../src/threat/model-generator.js';
import { parsePython } from '../../../src/engine/parser.js';
import { buildCFG } from '../../../src/engine/cfg.js';
import { buildProgramGraph } from '../../../src/engine/program-graph.js';
import { analyzeTaint } from '../../../src/engine/taint.js';
import type { PipelineResult } from '../../../src/plugin/types.js';

// 用真实 parser/CFG/graph/taint/model-generator 走完整代码路径,只 hook 掉 plugin 阶段:
// 这样既不污染模块全局 mock,又能验证 pipeline 编排逻辑与参数透传。
const pluginRuns: Array<{ args: unknown[] }> = [];
const realPluginRun = PluginPipeline.prototype.run;

function installSpy(): void {
  PluginPipeline.prototype.run = async function (...args: unknown[]): Promise<PipelineResult> {
    pluginRuns.push({ args });
    // 无插件注册的 PluginRegistry 在真实 PluginPipeline 下也会返回空结果
    return {
      findings: [],
      detections: [],
      enhancedDetections: [],
      timing: { probes: 0, detectors: 0, generators: 0, total: 0 },
      errors: [],
    };
  };
}

function uninstallSpy(): void {
  PluginPipeline.prototype.run = realPluginRun;
}

beforeEach(() => {
  pluginRuns.length = 0;
  installSpy();
});

afterAll(() => {
  uninstallSpy();
});

describe('ThreatModelPipeline.run — happy path', () => {
  test('returns a fully-shaped ThreatModelPipelineResult', async () => {
    const pipeline = new ThreatModelPipeline(new PluginRegistry());
    const result = await pipeline.run('x = 1\ny = x + 1', 'app.py');

    expect(result).toBeDefined();
    expect(result.threatModel).toBeDefined();
    expect(result.schedule).toBeArray();
    expect(result.pipelineResult).toBeDefined();
    expect(result.pipelineResult.findings).toBeArray();
    expect(result.pipelineResult.detections).toBeArray();
    expect(result.calibration).toBeDefined();
    expect(result.calibration.coverage).toBeDefined();
    expect(result.calibration.threatFindings instanceof Map).toBe(true);
  });

  test('result.threatModel.scope reflects the input filePath', async () => {
    const pipeline = new ThreatModelPipeline(new PluginRegistry());
    const result = await pipeline.run('x = 1', 'demo.py');
    expect(result.threatModel.scope).toBe('demo.py');
  });

  test('skipThreatModel=true produces an empty threat model', async () => {
    const pipeline = new ThreatModelPipeline(new PluginRegistry());
    const result = await pipeline.run('x = 1', 'app.py', { skipThreatModel: true });

    expect(result.threatModel.threats.length).toBe(0);
    expect(result.schedule.length).toBe(0);
    expect(result.calibration.coverage.threatsTotal).toBe(0);
    expect(result.calibration.coverage.coveragePercent).toBe(0);
  });
});

describe('ThreatModelPipeline.run — phase orchestration (real code paths)', () => {
  test('real pipeline exercises parser, CFG, graph, taint, threat model, and plugin phases', async () => {
    const code = 'def f(x):\n  return x + 1\n';
    const pipeline = new ThreatModelPipeline(new PluginRegistry());

    // 验证子阶段函数本身可调用 — 确认依赖图连通
    const parsed = parsePython(code);
    expect(parsed).toBeDefined();
    const cfg = buildCFG(parsed.ast);
    const graph = buildProgramGraph(parsed.ast, cfg ?? undefined, code);
    expect(graph.nodeCount).toBeGreaterThanOrEqual(1);
    const taint = analyzeTaint(code, 'global');
    expect(taint).toBeDefined();
    const threatModel = generateThreatModel(graph, taint, 'demo.py');
    expect(threatModel.scope).toBe('demo.py');

    // 跑完整 pipeline
    await pipeline.run(code, 'demo.py');

    // plugin 阶段确实被调用了一次,且参数透传正确
    expect(pluginRuns.length).toBe(1);
    expect(pluginRuns[0].args[0]).toBe(code);
    expect(pluginRuns[0].args[1]).toBe('demo.py');
  });

  test('plugin pipeline receives probeConfig and user config (language, minConfidence)', async () => {
    const pipeline = new ThreatModelPipeline(new PluginRegistry());
    await pipeline.run('def f(x):\n  return x + 1\n', 'app.py', { minConfidence: 0.7 });

    expect(pluginRuns.length).toBe(1);
    const cfg = pluginRuns[0].args[2] as Record<string, unknown>;
    expect(cfg.minConfidence).toBe(0.7);
    expect(cfg.language).toBe('python');
    expect(cfg.probeConfig).toBeDefined();
  });
});

describe('ThreatModelPipeline.run — error propagation (no try/catch)', () => {
  test('error from plugin pipeline propagates out of run() (no graceful degradation)', async () => {
    // 临时让 plugin 阶段抛错,验证上层无 try/catch 拦截
    uninstallSpy();
    PluginPipeline.prototype.run = async function (): Promise<PipelineResult> {
      throw new Error('plugin failure');
    };

    try {
      const pipeline = new ThreatModelPipeline(new PluginRegistry());
      await expect(pipeline.run('x = 1', 'app.py')).rejects.toThrow('plugin failure');
    } finally {
      installSpy();
    }
  });
});

describe('ThreatModelPipeline.run — timing fields', () => {
  test('records timing for every phase plus total', async () => {
    const pipeline = new ThreatModelPipeline(new PluginRegistry());
    const result = await pipeline.run('def f(x):\n  return x + 1\n', 'app.py');

    expect(result.timing).toBeDefined();
    expect(typeof result.timing.threatModelMs).toBe('number');
    expect(typeof result.timing.schedulingMs).toBe('number');
    expect(typeof result.timing.detectionMs).toBe('number');
    expect(typeof result.timing.calibrationMs).toBe('number');
    expect(typeof result.timing.totalMs).toBe('number');

    expect(result.timing.threatModelMs).toBeGreaterThanOrEqual(0);
    expect(result.timing.schedulingMs).toBeGreaterThanOrEqual(0);
    expect(result.timing.detectionMs).toBeGreaterThanOrEqual(0);
    expect(result.timing.calibrationMs).toBeGreaterThanOrEqual(0);
    expect(result.timing.totalMs).toBeGreaterThanOrEqual(0);

    expect(Number.isFinite(result.timing.totalMs)).toBe(true);
  });
});
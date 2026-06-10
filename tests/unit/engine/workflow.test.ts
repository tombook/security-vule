/**
 * Tests for6-stage multi-agent security review workflow.
 */
import { describe, expect, test } from 'bun:test';
import { Workflow } from '../../../src/engine/workflow.js';

describe('Workflow — initialization', () => {
  test('starts with all6 stages in pending status', () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    const summary = wf.summary();
    for (const s of ['SPEC', 'PLAN', 'BUILD', 'TEST', 'REVIEW', 'SHIP'] as const) {
      expect(summary.stages[s].status).toBe('pending');
    }
    expect(summary.progress.completed).toBe(0);
    expect(summary.progress.percent).toBe(0);
    expect(summary.result).toBe('pass');
  });

  test('stage order is SPEC → PLAN → BUILD → TEST → REVIEW → SHIP', () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    const summary = wf.summary();
    expect(Object.keys(summary.stages)).toEqual([
      'SPEC',
      'PLAN',
      'BUILD',
      'TEST',
      'REVIEW',
      'SHIP',
    ]);
  });
});

describe('Workflow — stage execution', () => {
  test('runStage updates status, duration, and output', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    const artifact = await wf.runStage('SPEC');
    expect(artifact.status).toBe('completed');
    expect(artifact.durationMs).toBeGreaterThanOrEqual(0);
    expect(artifact.output['scope']).toBe('app.php');
    expect(artifact.output['language']).toBe('php');
    expect(artifact.output['riskFactors']).toBeInstanceOf(Array);
  });

  test('SPEC identifies PHP risk factors (SQLi/XSS/RCE/LFI)', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    const artifact = await wf.runStage('SPEC');
    const factors = artifact.output['riskFactors'] as string[];
    expect(factors).toContain('sql-injection');
    expect(factors).toContain('xss');
    expect(factors).toContain('rce');
  });

  test('SPEC identifies Python risk factors (pickle/cmdi/ssrf)', async () => {
    const wf = new Workflow({ target: 'app.py', language: 'python' });
    const artifact = await wf.runStage('SPEC');
    const factors = artifact.output['riskFactors'] as string[];
    expect(factors).toContain('pickle-deserialization');
    expect(factors).toContain('command-injection');
  });

  test('PLAN selects dimensions based on config', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php', enableOwaspAgentic: true });
    const artifact = await wf.runStage('PLAN');
    const dims = artifact.output['enabledDimensions'] as string[];
    expect(dims).toContain('gravity');
    expect(dims).toContain('darkMatter');
    expect(artifact.output['owaspAgenticEnabled']).toBe(true);
    expect(artifact.output['strategy']).toBe('ast-only');
  });

  test('PLAN estimates cost correctly', async () => {
    const astOnly = await new Workflow({ target: 'app.php', language: 'php' }).runStage('PLAN');
    expect(astOnly.output['estimatedCostUsd']).toBe(0);
    const llmOn = await new Workflow({
      target: 'app.php',
      language: 'php',
      enableLlm: true,
    }).runStage('PLAN');
    expect(llmOn.output['estimatedCostUsd']).toBe(0.5);
  });

  test('BUILD constructs CPG with correct language', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    const artifact = await wf.runStage('BUILD');
    expect(artifact.output['cpgLanguage']).toBe('php');
    expect(typeof artifact.output['cpgNodeCount']).toBe('number');
  });

  test('REVIEW calculates topRisk ratio and verdict', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    await wf.runStage('SPEC');
    await wf.runStage('PLAN');
    await wf.runStage('BUILD');
    await wf.runStage('TEST');
    await wf.runStage('REVIEW');
    expect(wf.summary().stages.REVIEW.output['reviewVerdict']).toBe('clean');
  });
});

describe('Workflow — skip and resume', () => {
  test('skipStage marks stage as skipped', () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    wf.skipStage('TEST', 'no LLM keys available');
    const summary = wf.summary();
    expect(summary.stages.TEST.status).toBe('skipped');
    expect(summary.stages.TEST.error).toBe('no LLM keys available');
  });

  test('runAll skips over already-skipped stages', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    wf.skipStage('TEST', 'integration disabled');
    wf.skipStage('SHIP', 'dry-run mode');
    const summary = await wf.runAll();
    expect(summary.stages.SPEC.status).toBe('completed');
    expect(summary.stages.PLAN.status).toBe('completed');
    expect(summary.stages.TEST.status).toBe('skipped');
    expect(summary.stages.SHIP.status).toBe('skipped');
    expect(summary.result).toBe('partial');
  });

  test('resume resets stages from given stage onward', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    await wf.runStage('SPEC');
    await wf.runStage('PLAN');
    wf.resume('TEST');
    const summary = wf.summary();
    expect(summary.stages.SPEC.status).toBe('completed');
    expect(summary.stages.TEST.status).toBe('pending');
    expect(summary.stages.REVIEW.status).toBe('pending');
  });
});

describe('Workflow — progress and summary', () => {
  test('progress reflects completed count', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php' });
    await wf.runStage('SPEC');
    expect(wf.getProgress().completed).toBe(1);
    expect(wf.getProgress().percent).toBe(17);
  });

  test('summary includes config, stages, total duration', async () => {
    const wf = new Workflow({ target: 'app.php', language: 'php', enableLlm: true });
    const summary = await wf.runAll();
    expect(summary.config.target).toBe('app.php');
    expect(summary.config.enableLlm).toBe(true);
    expect(summary.totalDurationMs).toBeGreaterThanOrEqual(0);
    expect(summary.result).toBe('pass');
  });
});

describe('Workflow — onStageComplete hook', () => {
  test('callback is invoked per completed stage', async () => {
    const completed: string[] = [];
    const wf = new Workflow({
      target: 'app.php',
      language: 'php',
      onStageComplete: (a) => {
        completed.push(a.stage);
      },
    });
    await wf.runStage('SPEC');
    await wf.runStage('PLAN');
    expect(completed).toEqual(['SPEC', 'PLAN']);
  });
});

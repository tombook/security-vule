import { describe, it, expect } from 'bun:test';
import { buildAIBom, aiComponentFromProvider, formatAIBomTable } from '../../src/llm/ai-bom';

describe('AI-BOM', () => {
  it('builds a CycloneDX-AI 1.5 compliant BOM', () => {
    const bom = buildAIBom('myapp', '1.0.0', [
      aiComponentFromProvider('zhipu', 'glm-5.1'),
      aiComponentFromProvider('ollama', 'qwen2.5'),
    ]);
    expect(bom.bomFormat).toBe('CycloneDX-AI');
    expect(bom.specVersion).toBe('1.5');
    expect(bom.component.name).toBe('myapp');
    expect(bom.component.version).toBe('1.0.0');
    expect(bom.component['bom-ref']).toContain('myapp');
    expect(bom.components.length).toBe(2);
    expect(bom.serialNumber).toMatch(/^urn:uuid:/);
  });

  it('attaches privacy + compliance from provider registry', () => {
    const c = aiComponentFromProvider('anthropic', 'claude-sonnet-4-5');
    expect(c.privacy).toBe('no-train-mandatory');
    expect(c.deployment).toBe('cloud');
    expect(c.complianceCertifications).toContain('SOC 2 Type II');
    expect(c.riskScore).toBeDefined();
  });

  it('marks ollama as local + low risk', () => {
    const c = aiComponentFromProvider('ollama', 'qwen2.5');
    expect(c.privacy).toBe('local');
    expect(c.deployment).toBe('self-hosted');
    expect(c.riskScore).toBeLessThanOrEqual(20);
  });

  it('falls back to defaults for unknown provider', () => {
    const c = aiComponentFromProvider('unknown-vendor', 'unknown-model');
    expect(c.privacy).toBe('no-train-mandatory');
    expect(c.deployment).toBe('cloud');
  });

  it('includes rate limit when provided', () => {
    const c = aiComponentFromProvider('zhipu', 'glm-5.1', { tokens: 1_000_000, costUsd: 5, calls: 10_000 });
    expect(c.rateLimit?.tokens).toBe(1_000_000);
    expect(c.rateLimit?.costUsd).toBe(5);
  });

  it('formatAIBomTable renders markdown table', () => {
    const bom = buildAIBom('app', '2.0', [aiComponentFromProvider('zhipu', 'glm-5.1')]);
    const out = formatAIBomTable(bom);
    expect(out).toContain('AI Bill of Materials');
    expect(out).toContain('CycloneDX-AI 1.5');
    expect(out).toContain('zhipu');
    expect(out).toContain('glm-5.1');
    expect(out).toContain('ISO 27001');
  });

  it('each component gets a unique serial', () => {
    const bom1 = buildAIBom('a', '1.0', []);
    const bom2 = buildAIBom('a', '1.0', []);
    expect(bom1.serialNumber).not.toBe(bom2.serialNumber);
  });

  it('mock provider has riskScore 0', () => {
    const c = aiComponentFromProvider('mock', 'mock');
    expect(c.riskScore).toBe(0);
    expect(c.notes).toContain('Deterministic');
  });
});

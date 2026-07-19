import { describe, it, expect } from 'bun:test';
import { RateLimiter, redactSecrets, validateFinding, estimateCostUsd } from '../../src/llm/security';

describe('LLM chaos engineering', () => {
  it('chaos-1: network timeout (simulated by hitting rate limit) gracefully returns error', () => {
    const rl = new RateLimiter({ maxCalls: 0 });
    expect(() => rl.record(1, 1, 0.0001)).toThrow(/calls/);
  });

  it('chaos-2: rate limit returns descriptive error, not generic crash', () => {
    const rl = new RateLimiter({ maxTokens: 100, maxCostUsd: 5, maxCalls: 1000 });
    expect(() => rl.record(80, 30, 0.01)).toThrow(/tokens/);
    try { rl.record(80, 30, 0.01); } catch (e) {
      expect((e as Error).message).toContain('tokens');
    }
  });

  it('chaos-3: malformed JSON from LLM is rejected by validateFinding', () => {
    const malformed = [{ type: 42, severity: null, line: 'not a number', description: 123 }];
    for (const raw of malformed) {
      const v = validateFinding(raw, '<?php echo 1;');
      expect(v.valid).toBe(false);
    }
  });

  it('chaos-4: null/undefined LLM output is rejected', () => {
    expect(validateFinding(null, 'x').valid).toBe(false);
    expect(validateFinding(undefined, 'x').valid).toBe(false);
    expect(validateFinding({}, 'x').valid).toBe(false);
    expect(validateFinding({ random: 'object' }, 'x').valid).toBe(false);
  });

  it('chaos-5: LLM provider returns 0 tokens (degenerate response)', () => {
    const rl = new RateLimiter();
    rl.record(0, 0, 0);
    expect(rl.stats().callCount).toBe(1);
    expect(rl.stats().promptTokens + rl.stats().completionTokens).toBe(0);
  });

  it('chaos-6: huge token bill (provider billing error)', () => {
    const rl = new RateLimiter({ maxCostUsd: 1.0, maxTokens: 1e15, maxCalls: 1e9 });
    expect(() => rl.record(1000, 1000, 9999.0)).toThrow(/cost/);
  });

  it('chaos-7: redaction is idempotent', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const r1 = redactSecrets(`key1=${secret} key2=${secret} key3=${secret}`);
    const r2 = redactSecrets(r1.text);
    expect(r2.text).toBe(r1.text);
    expect(r2.redactions).toEqual([]);
  });

  it('chaos-8: validateFinding rejects finding where line exceeds file length', () => {
    const shortCode = '<?php\n$x = 1;';
    const r = validateFinding({ type: 'SQL Injection', severity: 'high', line: 999, description: 'A description that is long enough to pass the test', remediation: 'A remediation that is long enough to pass the test', codeSnippet: 'x', confidence: 0.5 }, shortCode);
    expect(r.valid).toBe(false);
    expect(r.reason).toContain('exceeds');
  });

  it('chaos-9: validateFinding rejects confidence outside [0, 1]', () => {
    const code = '<?php\n$x = $_GET["id"];';
    const r1 = validateFinding({ type: 'SQL Injection', severity: 'high', line: 2, description: 'long enough description for testing validation rules here', remediation: 'long enough remediation for testing validation rules here', codeSnippet: 'x', confidence: 5.0 }, code);
    expect(r1.finding?.confidence).toBeLessThanOrEqual(1.0);
  });

  it('chaos-10: cost estimation throws on unknown model (no silent low-bill)', () => {
    expect(() => estimateCostUsd('totally-unknown-model-xyz', 1000, 1000)).toThrow(/unknown/i);
  });

  it('chaos-11: rate limit stats are accessible even after exceptions', () => {
    const rl = new RateLimiter({ maxTokens: 100 });
    rl.record(50, 0, 0.001);
    try { rl.record(80, 30, 0.01); } catch { /* expected */ }
    const s = rl.stats();
    expect(s.promptTokens).toBe(50);
    expect(s.callCount).toBe(1);
    expect(s.completionTokens).toBe(0);
  });

  it('chaos-12: validateFinding with very long description does not crash', () => {
    const longDesc = 'a'.repeat(10000);
    const r = validateFinding({ type: 'SQL Injection', severity: 'high', line: 1, description: longDesc, remediation: longDesc, codeSnippet: 'x', confidence: 0.5 }, '<?php $x = $_GET["id"];');
    expect(r).toBeDefined();
  });
});

import { describe, it, expect } from 'bun:test';
import { AuditLogger } from '../../src/llm/audit';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('AuditLogger', () => {
  it('records entry to file sink', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-'));
    try {
      const logPath = join(dir, 'audit.log');
      const logger = AuditLogger.toFile(logPath);
      logger.record({
        fileHash: 'abc123def456',
        fileSize: 1024,
        language: 'php',
        provider: 'zhipu',
        model: 'glm-5.1',
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
        costUsd: 0.001,
        durationMs: 200,
        redactions: [],
        injectionDetected: false,
        injectionRiskScore: 0,
        findingsAccepted: 2,
        findingsRejected: 0,
        rateLimitReached: false,
        outcome: 'success',
      });
      const content = readFileSync(logPath, 'utf-8');
      expect(content).toContain('"provider":"zhipu"');
      expect(content).toContain('"model":"glm-5.1"');
      expect(content).toContain('"fileHash":"abc123def456"');
      expect(content).not.toContain('code');
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('hashes file content deterministically', () => {
    const logger = new AuditLogger();
    const h1 = logger.hash('hello world');
    const h2 = logger.hash('hello world');
    const h3 = logger.hash('hello WORLD');
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1.length).toBe(16);
  });

  it('aggregates summary stats', () => {
    const logger = new AuditLogger();
    logger.record({ fileHash: 'a', fileSize: 100, provider: 'zhipu', model: 'glm-5.1', promptTokens: 10, completionTokens: 5, totalTokens: 15, costUsd: 0.001, durationMs: 100, redactions: [], injectionDetected: false, injectionRiskScore: 0, findingsAccepted: 0, findingsRejected: 0, rateLimitReached: false, outcome: 'success' });
    logger.record({ fileHash: 'b', fileSize: 200, provider: 'anthropic', model: 'claude-sonnet-4-5', promptTokens: 20, completionTokens: 10, totalTokens: 30, costUsd: 0.05, durationMs: 200, redactions: [], injectionDetected: true, injectionRiskScore: 3, findingsAccepted: 1, findingsRejected: 0, rateLimitReached: false, outcome: 'injection_detected' });
    const s = logger.summary();
    expect(s.totalCalls).toBe(2);
    expect(s.totalTokens).toBe(45);
    expect(s.totalCostUsd).toBeCloseTo(0.051, 6);
    expect(s.byProvider.zhipu).toBe(1);
    expect(s.byProvider.anthropic).toBe(1);
    expect(s.byOutcome.success).toBe(1);
    expect(s.byOutcome.injection_detected).toBe(1);
  });

  it('formats a dashboard with provider/outcome breakdown', () => {
    const logger = new AuditLogger();
    logger.record({ fileHash: 'a', fileSize: 100, provider: 'ollama', model: 'qwen2.5', promptTokens: 100, completionTokens: 50, totalTokens: 150, costUsd: 0, durationMs: 100, redactions: [], injectionDetected: false, injectionRiskScore: 0, findingsAccepted: 3, findingsRejected: 0, rateLimitReached: false, outcome: 'success' });
    const dash = logger.formatDashboard();
    expect(dash).toContain('LLM Cost Dashboard');
    expect(dash).toContain('ollama');
    expect(dash).toContain('$0.0000 USD');
  });
});

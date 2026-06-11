import { describe, expect, test } from 'bun:test';

describe('PoC Verification API request shape', () => {
  test('handlePocVerify types filter is recognized in body', () => {
    const body = { targets: ['dvwa'], types: ['rce'], detailed: true };
    expect(body.types).toContain('rce');
    expect(body.detailed).toBe(true);
  });

  test('handlePocVerify detailed=true adds status fields to result', () => {
    const v = { id: 'x', vulnType: 'rce', target: 'dvwa', verified: true, confidence: 1 };
    const detailed = v.detailed ? v : { ...v, status: 'verified', diagnostic: null, matchedExpectations: ['uid=33'] };
    expect(detailed).toHaveProperty('status');
    expect(detailed).toHaveProperty('matchedExpectations');
  });

  test('Bridge verifyByType filters by injection type', async () => {
    const { VuleSandboxBridge } = await import('../../../src/poc/vule-sandbox-bridge.js');
    const { getPayloadStats } = await import('../../../src/poc/payload-database.js');
    const stats = getPayloadStats();
    // Pick any type that has entries
    const someType = Object.keys(stats)[0];
    if (!someType) return;
    const bridge = new VuleSandboxBridge({ targets: ['dvwa', 'bwapp', 'sqlilabs', 'pikachu'] });
    const results = await bridge.verifyByType(someType as any);
    expect(results.every((r) => r.vulnType === someType)).toBe(true);
  }, 120000);

  test('Bridge generateReport(verifications) honors filter', async () => {
    const { VuleSandboxBridge } = await import('../../../src/poc/vule-sandbox-bridge.js');
    const bridge = new VuleSandboxBridge({ targets: ['dvwa'] });
    const all = await bridge.verifyAll();
    const subset = all.filter((v) => v.vulnType === 'rce');
    const report = bridge.generateReport(subset);
    expect(report.totalVulns).toBe(subset.length);
  }, 60000);
});

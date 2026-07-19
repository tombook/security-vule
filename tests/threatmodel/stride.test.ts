import { describe, it, expect } from 'bun:test';
import { categorizeByStride, buildThreatModel, STRIDE_FULL_NAME } from '../../src/threatmodel/stride';

describe('STRIDE threat model', () => {
  it('categorizes SQL injection as Tampering + Information Disclosure', () => {
    const cats = categorizeByStride('sql');
    expect(cats).toContain('T');
    expect(cats).toContain('I');
  });

  it('categorizes weak random as Spoofing', () => {
    expect(categorizeByStride('weakrand')).toEqual(['S']);
  });

  it('categorizes shell command injection as Tampering + EoP', () => {
    const cats = categorizeByStride('shell');
    expect(cats).toContain('T');
    expect(cats).toContain('E');
  });

  it('returns default Tampering for unknown types', () => {
    expect(categorizeByStride('xxx_unknown')).toEqual(['T']);
  });

  it('STRIDE_FULL_NAME has all 6 categories', () => {
    expect(Object.keys(STRIDE_FULL_NAME).sort()).toEqual(['D', 'E', 'I', 'R', 'S', 'T']);
  });

  it('buildThreatModel aggregates by STRIDE category', () => {
    const findings = [
      { type: 'sql', cwe: 'CWE-89', file: 'a.php', line: 1, confidence: 0.9, severity: 'CRITICAL' },
      { type: 'weakrand', cwe: 'CWE-330', file: 'a.php', line: 2, confidence: 0.7, severity: 'MEDIUM' },
      { type: 'xss', cwe: 'CWE-79', file: 'a.php', line: 3, confidence: 0.8, severity: 'HIGH' },
    ];
    const tm = buildThreatModel('/target', findings);
    expect(tm.totalThreats).toBeGreaterThan(0);
    expect(tm.byStride.S).toBe(1);
    expect(tm.byStride.T).toBe(2);
    expect(tm.byStride.I).toBe(1);
    expect(tm.target).toBe('/target');
  });
});

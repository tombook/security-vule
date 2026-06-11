/**
 * Tests for Threat Model generator (Anthropic Harness /threat-model skill).
 */
import { describe, expect, test } from 'bun:test';
import { generateThreatModel } from '../../../src/threatmodel/threat-model.js';

const phpAppOptions = {
  projectName: 'demo-php-app',
  language: 'php' as const,
  sourceFiles: [
    { path: 'public/api/users.php', lines: 200 },
    { path: 'auth/login.php', lines: 80 },
    { path: 'admin/dashboard.php', lines: 150 },
    { path: 'lib/db.php', lines: 50 },
    { path: 'payment/checkout.php', lines: 300 },
  ],
  entryPoints: ['/api/users', '/login', '/admin'],
  dataStores: ['mysql:users_db'],
  knownUserInputs: ['$_GET', '$_POST'],
};

describe('generateThreatModel — structure', () => {
  test('returns all required sections', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.projectName).toBe('demo-php-app');
    expect(tm.trustBoundaries.length).toBeGreaterThan(0);
    expect(tm.assets.length).toBeGreaterThan(0);
    expect(tm.adversaries.length).toBeGreaterThan(0);
    expect(tm.attackSurfaces.length).toBeGreaterThan(0);
    expect(tm.threats.length).toBeGreaterThan(0);
    expect(tm.recommendations.length).toBeGreaterThan(0);
    expect(tm.markdown.length).toBeGreaterThan(200);
    expect(tm.json).toBeDefined();
  });

  test('markdown contains all section headers', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.markdown).toContain('# Threat Model: demo-php-app');
    expect(tm.markdown).toContain('##1. System Overview');
    expect(tm.markdown).toContain('##2. Trust Boundaries');
    expect(tm.markdown).toContain('##3. Assets');
    expect(tm.markdown).toContain('##4. Adversaries');
    expect(tm.markdown).toContain('##5. Attack Surface');
    expect(tm.markdown).toContain('##6. Threats');
    expect(tm.markdown).toContain('##7. Recommendations');
  });
});

describe('generateThreatModel — inference', () => {
  test('infers database boundary when MySQL detected', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.trustBoundaries).toContain('Database');
  });

  test('infers authentication boundary from auth files', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.trustBoundaries).toContain('Authentication');
  });

  test('infers admin boundary from admin files', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.trustBoundaries).toContain('Admin panel');
  });

  test('classifies user files as PII', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.assets.some((a) => a.name === 'User accounts' && a.classification === 'pii')).toBe(
      true
    );
  });

  test('classifies payment files as confidential', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(
      tm.assets.some((a) => a.name === 'Payment data' && a.classification === 'confidential')
    ).toBe(true);
  });

  test('classifies database as confidential', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(
      tm.assets.some((a) => a.name === 'Database' && a.classification === 'confidential')
    ).toBe(true);
  });
});

describe('generateThreatModel — threats', () => {
  test('generates tampering threat for each entry point', () => {
    const tm = generateThreatModel(phpAppOptions);
    const tampering = tm.threats.filter((t) => t.stride === 'Tampering');
    expect(tampering.length).toBe(phpAppOptions.entryPoints!.length);
  });

  test('generates spoofing threat when auth files present', () => {
    const tm = generateThreatModel(phpAppOptions);
    const spoofing = tm.threats.filter((t) => t.stride === 'Spoofing');
    expect(spoofing.length).toBeGreaterThan(0);
    expect(spoofing[0]?.severity).toBe('CRITICAL');
  });

  test('generates information disclosure threat when PII present', () => {
    const tm = generateThreatModel(phpAppOptions);
    const infoDisc = tm.threats.filter((t) => t.stride === 'Information Disclosure');
    expect(infoDisc.length).toBeGreaterThan(0);
  });

  test('all threats have unique IDs', () => {
    const tm = generateThreatModel(phpAppOptions);
    const ids = new Set(tm.threats.map((t) => t.id));
    expect(ids.size).toBe(tm.threats.length);
  });

  test('threats table contains all threat rows', () => {
    const tm = generateThreatModel(phpAppOptions);
    for (const t of tm.threats) {
      expect(tm.markdown).toContain(t.id);
      expect(tm.markdown).toContain(t.title);
    }
  });
});

describe('generateThreatModel — JSON output', () => {
  test('produces valid ThreatModel JSON for triage engine', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.json.internetFacing).toContain('public/api/users.php');
    expect(tm.json.dataClassification['user']).toBe('pii');
    expect(tm.json.criticalAssets).toContain('user');
  });

  test('critical assets include PII locations', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.json.criticalAssets.length).toBeGreaterThan(0);
  });
});

describe('generateThreatModel — recommendations', () => {
  test('recommendations include addressing CRITICAL threats', () => {
    const tm = generateThreatModel(phpAppOptions);
    const hasCrit = tm.threats.some((t) => t.severity === 'CRITICAL');
    const hasRec = tm.recommendations.some((r) => r.includes('CRITICAL'));
    expect(hasRec).toBe(hasCrit);
  });

  test('always recommends automated scanning', () => {
    const tm = generateThreatModel(phpAppOptions);
    expect(tm.recommendations.some((r) => r.toLowerCase().includes('scanning'))).toBe(true);
  });
});

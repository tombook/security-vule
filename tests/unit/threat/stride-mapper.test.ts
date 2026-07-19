import { describe, test, expect } from 'bun:test';
import {
  STRIDE_MAPPINGS,
  classifySourceSink,
  getCategoriesForSourceSink,
  computeThreatPriority,
  mapBoundaryType,
  type STRIDEMapping,
} from '../../../src/threat/stride-mapper.js';

describe('stride-mapper: STRIDE_MAPPINGS data', () => {
  test('has mappings', () => {
    expect(STRIDE_MAPPINGS.length).toBeGreaterThan(0);
  });

  test('all mappings have required fields', () => {
    for (const m of STRIDE_MAPPINGS) {
      expect(m.category).toBeDefined();
      expect(m.sourceType).toBeDefined();
      expect(m.sinkType).toBeDefined();
      expect(m.cweIds.length).toBeGreaterThan(0);
      expect(m.owasp).toBeDefined();
      expect(m.rulePrefixes.length).toBeGreaterThan(0);
    }
  });

  test('covers all 6 STRIDE categories', () => {
    const categories = new Set(STRIDE_MAPPINGS.map(m => m.category));
    expect(categories.has('tampering')).toBe(true);
    expect(categories.has('spoofing')).toBe(true);
    expect(categories.has('repudiation')).toBe(true);
    expect(categories.has('information_disclosure')).toBe(true);
    expect(categories.has('denial_of_service')).toBe(true);
    expect(categories.has('elevation_of_privilege')).toBe(true);
  });

  test('all CWE IDs follow CWE-N format', () => {
    for (const m of STRIDE_MAPPINGS) {
      for (const cwe of m.cweIds) {
        expect(cwe).toMatch(/^CWE-\d+$/);
      }
    }
  });
});

describe('stride-mapper: classifySourceSink', () => {
  test('classifies user_input → sql as tampering', () => {
    const matches = classifySourceSink('user_input', 'sql');
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.category === 'tampering')).toBe(true);
  });

  test('classifies cookie → sql as spoofing + repudiation', () => {
    const matches = classifySourceSink('cookie', 'sql');
    expect(matches.length).toBeGreaterThanOrEqual(2);
    const categories = matches.map(m => m.category);
    expect(categories).toContain('spoofing');
    expect(categories).toContain('repudiation');
  });

  test('returns empty for unknown combo', () => {
    const matches = classifySourceSink('env', 'deserialization');
    expect(matches).toBeArray();
  });

  test('classifies network → shell as elevation_of_privilege', () => {
    const matches = classifySourceSink('network', 'shell');
    expect(matches.some(m => m.category === 'elevation_of_privilege')).toBe(true);
  });
});

describe('stride-mapper: getCategoriesForSourceSink', () => {
  test('returns unique categories', () => {
    const cats = getCategoriesForSourceSink('user_input', 'shell');
    expect(cats.length).toBeGreaterThan(0);
    expect(new Set(cats).size).toBe(cats.length);
  });

  test('returns empty for unknown combo', () => {
    const cats = getCategoriesForSourceSink('env', 'deserialization');
    expect(cats).toBeArray();
  });

  test('returns multiple categories for cookie/sql', () => {
    const cats = getCategoriesForSourceSink('cookie', 'sql');
    expect(cats.length).toBeGreaterThanOrEqual(2);
  });
});

describe('stride-mapper: computeThreatPriority', () => {
  test('higher confidence increases priority', () => {
    const p1 = computeThreatPriority('tampering', 0.5, false);
    const p2 = computeThreatPriority('tampering', 1.0, false);
    expect(p2).toBeGreaterThan(p1);
  });

  test('sanitizer reduces priority', () => {
    const p1 = computeThreatPriority('tampering', 1.0, false);
    const p2 = computeThreatPriority('tampering', 1.0, true);
    expect(p2).toBeLessThan(p1);
  });

  test('tampering has highest base weight', () => {
    const tamperingP = computeThreatPriority('tampering', 1.0, false);
    const repudiationP = computeThreatPriority('repudiation', 1.0, false);
    expect(tamperingP).toBeGreaterThan(repudiationP);
  });

  test('priority is bounded 0-100', () => {
    const p = computeThreatPriority('elevation_of_privilege', 1.0, false);
    expect(p).toBeGreaterThanOrEqual(0);
    expect(p).toBeLessThanOrEqual(100);
  });

  test('confidence=0 returns 0', () => {
    const p = computeThreatPriority('tampering', 0, false);
    expect(p).toBe(0);
  });
});

describe('stride-mapper: mapBoundaryType', () => {
  test('network sources map to network boundary', () => {
    expect(mapBoundaryType('network', 'sql')).toBe('network');
    expect(mapBoundaryType('header', 'sql')).toBe('network');
    expect(mapBoundaryType('cookie', 'sql')).toBe('network');
  });

  test('db sources map to data_store boundary', () => {
    expect(mapBoundaryType('db', 'eval')).toBe('data_store');
    expect(mapBoundaryType('file_io', 'eval')).toBe('data_store');
  });

  test('sql sinks map to data_store boundary', () => {
    expect(mapBoundaryType('user_input', 'sql')).toBe('data_store');
    expect(mapBoundaryType('user_input', 'db' as any)).toBe('data_store');
  });

  test('network_send sinks map to output boundary', () => {
    expect(mapBoundaryType('user_input', 'network_send')).toBe('output');
  });

  test('shell/eval sinks map to process boundary', () => {
    expect(mapBoundaryType('user_input', 'shell')).toBe('process');
    expect(mapBoundaryType('user_input', 'eval')).toBe('process');
    expect(mapBoundaryType('user_input', 'dynamic_code')).toBe('process');
  });

  test('defaults to input boundary', () => {
    expect(mapBoundaryType('user_input', 'file_write' as any)).toBe('input');
  });
});

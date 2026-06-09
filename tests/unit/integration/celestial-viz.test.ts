import { describe, test, expect } from 'bun:test';
import {
  renderGalaxy,
  renderGalaxyWithLegend,
  computeBarycenter,
  computeTotalEnergy,
  classifyBodies,
  DEFAULT_GALAXY_CONFIG,
  type CelestialBody,
} from '../../../src/integration/celestial-viz.js';

const SAMPLE_BODIES: CelestialBody[] = [
  { id: 'src1', name: 'user input', position: { x: -10, y: 5, z: 5 }, mass: 1.0, risk: 0.7, type: 'source' },
  { id: 'src2', name: 'request args', position: { x: 8, y: -3, z: 8 }, mass: 0.8, risk: 0.6, type: 'source' },
  { id: 'sink1', name: 'db.execute', position: { x: 0, y: 0, z: 10 }, mass: 2.0, risk: 0.9, type: 'sink' },
  { id: 'sink2', name: 'os.system', position: { x: 5, y: 8, z: 12 }, mass: 1.5, risk: 0.95, type: 'sink' },
  { id: 'san1', name: 'html.escape', position: { x: -5, y: -5, z: 7 }, mass: 0.5, risk: 0.3, type: 'sanitizer' },
  { id: 'crit1', name: 'eval()', position: { x: 12, y: 0, z: 15 }, mass: 3.0, risk: 1.0, type: 'critical' },
];

describe('celestial-viz: renderGalaxy', () => {
  test('produces string of correct dimensions', () => {
    const out = renderGalaxy(SAMPLE_BODIES, { width: 40, height: 10 });
    const lines = out.split('\n');
    expect(lines.length).toBe(10);
    for (const line of lines) {
      expect(line.length).toBeGreaterThan(0);
    }
  });

  test('uses default config when none provided', () => {
    const out = renderGalaxy(SAMPLE_BODIES);
    const lines = out.split('\n');
    expect(lines.length).toBe(DEFAULT_GALAXY_CONFIG.height);
  });

  test('renders empty string for empty bodies', () => {
    const out = renderGalaxy([], { width: 20, height: 5 });
    expect(out).toBeDefined();
    expect(out.length).toBeGreaterThan(0);
  });

  test('includes ANSI color codes for visible bodies', () => {
    const out = renderGalaxy(SAMPLE_BODIES, { width: 80, height: 24 });
    expect(out).toContain('\x1b[');
  });

  test('handles bodies behind camera gracefully', () => {
    const behind: CelestialBody[] = [
      { id: 'behind', position: { x: 0, y: 0, z: -5 }, mass: 1, risk: 1, type: 'sink' },
    ];
    const out = renderGalaxy(behind, { width: 20, height: 5, camera: { x: 0, y: 0, z: 10 } });
    expect(out).toBeDefined();
  });
});

describe('celestial-viz: renderGalaxyWithLegend', () => {
  test('includes legend', () => {
    const out = renderGalaxyWithLegend(SAMPLE_BODIES, { width: 60, height: 12 });
    expect(out).toContain('Celestial Mechanics Risk Map');
    expect(out).toContain('Bodies:');
  });

  test('legend shows body count', () => {
    const out = renderGalaxyWithLegend(SAMPLE_BODIES, { width: 60, height: 12 });
    expect(out).toContain('Bodies: 6');
  });

  test('legend shows camera position', () => {
    const out = renderGalaxyWithLegend(SAMPLE_BODIES, { width: 60, height: 12, camera: { x: 5, y: 5, z: 30 } });
    expect(out).toContain('Camera: (5, 5, 30)');
  });

  test('legend shows rotation values', () => {
    const out = renderGalaxyWithLegend(SAMPLE_BODIES, { width: 60, height: 12, yaw: 0.5, pitch: 0.3 });
    expect(out).toContain('Yaw: 0.50 rad');
    expect(out).toContain('Pitch: 0.30 rad');
  });

  test('legend shows type colors', () => {
    const out = renderGalaxyWithLegend(SAMPLE_BODIES, { width: 60, height: 12 });
    expect(out).toContain('source');
    expect(out).toContain('sink');
    expect(out).toContain('sanitizer');
    expect(out).toContain('critical');
  });
});

describe('celestial-viz: computeBarycenter', () => {
  test('center of mass for symmetric system is at origin', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
      { id: 'b', position: { x: -1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
    ];
    const com = computeBarycenter(bodies);
    expect(Math.abs(com.x)).toBeLessThan(0.001);
  });

  test('heavier body pulls center of mass toward it', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
      { id: 'b', position: { x: 10, y: 0, z: 0 }, mass: 9, risk: 0, type: 'neutral' },
    ];
    const com = computeBarycenter(bodies);
    expect(com.x).toBeCloseTo(9, 1);
  });

  test('empty bodies return origin', () => {
    const com = computeBarycenter([]);
    expect(com.x).toBe(0);
    expect(com.y).toBe(0);
    expect(com.z).toBe(0);
  });

  test('zero mass bodies return origin', () => {
    const com = computeBarycenter([{ id: 'a', position: { x: 5, y: 5, z: 5 }, mass: 0, risk: 0, type: 'neutral' }]);
    expect(com.x).toBe(0);
  });
});

describe('celestial-viz: computeTotalEnergy', () => {
  test('kinetic energy from risk levels', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 2, type: 'sink' },
    ];
    const e = computeTotalEnergy(bodies);
    expect(e).toBeGreaterThan(0);
  });

  test('negative potential energy from two bodies', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'sink' },
      { id: 'b', position: { x: 1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'source' },
    ];
    const e = computeTotalEnergy(bodies);
    expect(e).toBeLessThan(0);
  });

  test('zero energy for single body', () => {
    const e = computeTotalEnergy([
      { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
    ]);
    expect(e).toBe(0);
  });

  test('empty array returns 0', () => {
    expect(computeTotalEnergy([])).toBe(0);
  });
});

describe('celestial-viz: classifyBodies', () => {
  test('counts by type', () => {
    const counts = classifyBodies(SAMPLE_BODIES);
    expect(counts.sources).toBe(2);
    expect(counts.sinks).toBe(2);
    expect(counts.sanitizers).toBe(1);
    expect(counts.critical).toBe(1);
    expect(counts.neutral).toBe(0);
  });

  test('all neutral when only neutral bodies', () => {
    const counts = classifyBodies([
      { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
      { id: 'b', position: { x: 1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
    ]);
    expect(counts.neutral).toBe(2);
    expect(counts.sources + counts.sinks + counts.sanitizers + counts.critical).toBe(0);
  });

  test('empty array returns zero counts', () => {
    const counts = classifyBodies([]);
    expect(counts.sources).toBe(0);
    expect(counts.sinks).toBe(0);
    expect(counts.sanitizers).toBe(0);
    expect(counts.critical).toBe(0);
    expect(counts.neutral).toBe(0);
  });
});

describe('celestial-viz: rotation', () => {
  test('yaw rotates positions', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 10, y: 0, z: 0 }, mass: 1, risk: 0.5, type: 'source' },
    ];
    const out1 = renderGalaxy(bodies, { width: 40, height: 10, yaw: 0 });
    const out2 = renderGalaxy(bodies, { width: 40, height: 10, yaw: Math.PI / 2 });
    expect(out1).not.toBe(out2);
  });

  test('pitch rotates positions', () => {
    const bodies: CelestialBody[] = [
      { id: 'a', position: { x: 0, y: 10, z: 0 }, mass: 1, risk: 0.5, type: 'source' },
    ];
    const out1 = renderGalaxy(bodies, { width: 40, height: 10, pitch: 0 });
    const out2 = renderGalaxy(bodies, { width: 40, height: 10, pitch: Math.PI / 4 });
    expect(out1).not.toBe(out2);
  });
});

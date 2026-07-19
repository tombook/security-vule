import { describe, it, expect } from 'bun:test';

describe('cosm-x-galaxy input validation', () => {
  it('rejects eccentricity >= 1', async () => {
    const { meanToTrueAnomaly } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => meanToTrueAnomaly(100, 1.5)).toThrow(/eccentricity/i);
  });

  it('rejects negative eccentricity', async () => {
    const { meanToTrueAnomaly } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => meanToTrueAnomaly(100, -0.5)).toThrow();
  });

  it('rejects NaN mean anomaly', async () => {
    const { meanToTrueAnomaly } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => meanToTrueAnomaly(NaN, 0.5)).toThrow();
  });

  it('rejects NaN eccentricity', async () => {
    const { meanToTrueAnomaly } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => meanToTrueAnomaly(1.0, NaN)).toThrow();
  });

  it('computes valid input correctly', async () => {
    const { meanToTrueAnomaly } = await import('../../../src/math/cosm-x-galaxy.js');
    const result = meanToTrueAnomaly(0.5, 0.3);
    expect(Number.isFinite(result)).toBe(true);
  });

  it('solveKeplerEquation rejects NaN mean anomaly', async () => {
    const { solveKeplerEquation } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => solveKeplerEquation(NaN, 0.3)).toThrow();
  });

  it('solveKeplerEquation rejects eccentricity >= 1', async () => {
    const { solveKeplerEquation } = await import('../../../src/math/cosm-x-galaxy.js');
    expect(() => solveKeplerEquation(1.0, 1.5)).toThrow(/eccentricity/i);
  });
});

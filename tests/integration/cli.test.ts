import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'child_process';

describe('CLI smoke tests', () => {
  test('vule --version', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', '--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.toString()).toContain('0.3.0');
  });
  test('vule list-dimensions shows gravity', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', 'list-dimensions']);
    expect(r.status).toBe(0);
    const out = r.stdout.toString();
    expect(out).toContain('gravity');
    expect(out).toContain('kepler');
    expect(out).toContain('perturbation');
  });
  test('vule dimension unknown exits with error', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', 'dimension', 'nonexistent', 'package.json']);
    expect(r.status).not.toBe(0);
  });
  test('vule dimension gravity runs on a real PHP file', () => {
    const r = spawnSync('bun', ['--bun', 'src/integration/vule-cli.ts', 'dimension', 'gravity', 'test-targets/php-vulns/dvwa_sqli_low.php']);
    expect(r.status).toBe(0);
    expect(r.stdout.toString()).toContain('Dimension: gravity');
  });
});
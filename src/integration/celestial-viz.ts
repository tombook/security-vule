/**
 * Celestial Mechanics Visualization
 *
 * Renders 3D N-body vulnerability risk positions as terminal ASCII art.
 * Uses inverse-square distance to map vulnerability positions to brightness,
 * with risk level driving the character glyph (· * # @).
 *
 * Physics:
 *   - Each node has (x, y, z) position and risk mass
 *   - Project (x, y, z) → 2D screen (perspective divide)
 *   - Risk intensity ∝ mass / distance²
 *   - Output as grid of characters with ANSI color codes
 */

export interface CelestialBody {
  id: string;
  name?: string;
  position: { x: number; y: number; z: number };
  mass: number;
  risk: number;
  type: 'source' | 'sink' | 'sanitizer' | 'neutral' | 'critical';
}

export interface GalaxyConfig {
  width: number;
  height: number;
  perspective: number;
  camera: { x: number; y: number; z: number };
  /** Optional: rotation in radians around Y axis */
  yaw?: number;
  /** Optional: rotation in radians around X axis */
  pitch?: number;
}

export const DEFAULT_GALAXY_CONFIG: GalaxyConfig = {
  width: 80,
  height: 24,
  perspective: 8,
  camera: { x: 0, y: 0, z: 30 },
};

const GLYPHS: Record<number, string> = {
  0: '·',
  1: '.',
  2: '·',
  3: '*',
  4: '+',
  5: 'x',
  6: '#',
  7: '@',
  8: '█',
};

const COLORS: Record<CelestialBody['type'], string> = {
  source: '\x1b[36m',
  sink: '\x1b[31m',
  sanitizer: '\x1b[32m',
  neutral: '\x1b[37m',
  critical: '\x1b[35m',
};

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function rotateY(p: { x: number; y: number; z: number }, yaw: number): { x: number; y: number; z: number } {
  const c = Math.cos(yaw), s = Math.sin(yaw);
  return { x: p.x * c - p.z * s, y: p.y, z: p.x * s + p.z * c };
}

function rotateX(p: { x: number; y: number; z: number }, pitch: number): { x: number; y: number; z: number } {
  const c = Math.cos(pitch), s = Math.sin(pitch);
  return { x: p.x, y: p.y * c - p.z * s, z: p.y * s + p.z * c };
}

function project(body: CelestialBody, config: GalaxyConfig): { x: number; y: number; z: number; intensity: number } | null {
  let p = { ...body.position };
  if (config.yaw) p = rotateY(p, config.yaw);
  if (config.pitch) p = rotateX(p, config.pitch);

  const dx = p.x - config.camera.x;
  const dy = p.y - config.camera.y;
  const dz = p.z - config.camera.z;
  if (dz >= 0) return null;

  const absDz = -dz;
  const factor = config.perspective / absDz;
  const screenX = Math.round(dx * factor + config.width / 2);
  const screenY = Math.round(dy * factor + config.height / 2);

  if (screenX < 0 || screenX >= config.width || screenY < 0 || screenY >= config.height) return null;

  const distSq = dx * dx + dy * dy + dz * dz;
  const intensity = Math.min(8, Math.max(0, Math.round(body.risk * 50 / Math.sqrt(distSq))));

  return { x: screenX, y: screenY, z: absDz, intensity };
}

interface ScreenCell {
  glyph: string;
  color: string;
  intensity: number;
  body?: CelestialBody;
}

function initGrid(width: number, height: number): ScreenCell[][] {
  return Array.from({ length: height }, () =>
    Array.from({ length: width }, () => ({ glyph: ' ', color: '', intensity: -1, body: undefined as CelestialBody | undefined }))
  );
}

export function renderGalaxy(bodies: CelestialBody[], config: Partial<GalaxyConfig> = {}): string {
  const cfg = { ...DEFAULT_GALAXY_CONFIG, ...config };
  const grid = initGrid(cfg.width, cfg.height);

  for (const body of bodies) {
    const proj = project(body, cfg);
    if (!proj) continue;
    const cell = grid[proj.y][proj.x];
    if (proj.intensity > cell.intensity) {
      cell.glyph = GLYPHS[proj.intensity] || ' ';
      cell.color = COLORS[body.type] || COLORS.neutral;
      cell.intensity = proj.intensity;
      cell.body = body;
    }
  }

  const lines: string[] = [];
  for (const row of grid) {
    let line = '';
    for (const cell of row) {
      if (cell.intensity < 0) {
        line += ' ';
      } else {
        line += cell.color + cell.glyph + RESET;
      }
    }
    lines.push(line);
  }
  return lines.join('\n');
}

export function renderGalaxyWithLegend(bodies: CelestialBody[], config: Partial<GalaxyConfig> = {}): string {
  const galaxy = renderGalaxy(bodies, config);
  const legend = [
    '',
    `${BOLD}Celestial Mechanics Risk Map${RESET}`,
    `${DIM}─────────────────────────────────────${RESET}`,
    `${COLORS.source}●${RESET} source    ${COLORS.sink}●${RESET} sink    ${COLORS.sanitizer}●${RESET} sanitizer    ${COLORS.critical}●${RESET} critical`,
    '',
    `Bodies: ${bodies.length}`,
    `Camera: (${config.camera?.x ?? 0}, ${config.camera?.y ?? 0}, ${config.camera?.z ?? 50})`,
    `Yaw: ${config.yaw?.toFixed(2) ?? '0.00'} rad    Pitch: ${config.pitch?.toFixed(2) ?? '0.00'} rad`,
  ].join('\n');
  return galaxy + '\n' + legend;
}

export function computeBarycenter(bodies: CelestialBody[]): { x: number; y: number; z: number } {
  let totalMass = 0;
  let cx = 0, cy = 0, cz = 0;
  for (const b of bodies) {
    totalMass += b.mass;
    cx += b.position.x * b.mass;
    cy += b.position.y * b.mass;
    cz += b.position.z * b.mass;
  }
  if (totalMass === 0) return { x: 0, y: 0, z: 0 };
  return { x: cx / totalMass, y: cy / totalMass, z: cz / totalMass };
}

export function computeTotalEnergy(bodies: CelestialBody[]): number {
  let ke = 0;
  for (const b of bodies) {
    ke += 0.5 * b.mass * b.risk * b.risk;
  }
  let pe = 0;
  for (let i = 0; i < bodies.length; i++) {
    for (let j = i + 1; j < bodies.length; j++) {
      const a = bodies[i], b = bodies[j];
      const dx = a.position.x - b.position.x;
      const dy = a.position.y - b.position.y;
      const dz = a.position.z - b.position.z;
      const r = Math.sqrt(dx * dx + dy * dy + dz * dz);
      if (r > 0) pe -= (a.mass * b.mass) / r;
    }
  }
  return ke + pe;
}

export function classifyBodies(bodies: CelestialBody[]): { critical: number; sources: number; sinks: number; sanitizers: number; neutral: number } {
  const counts = { critical: 0, sources: 0, sinks: 0, sanitizers: 0, neutral: 0 };
  for (const b of bodies) {
    if (b.type === 'source') counts.sources++;
    else if (b.type === 'sink') counts.sinks++;
    else if (b.type === 'sanitizer') counts.sanitizers++;
    else if (b.type === 'critical') counts.critical++;
    else counts.neutral++;
  }
  return counts;
}

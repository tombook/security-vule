/**
 * Threat model generator — /threat-model skill (Anthropic Harness).
 *
 * Generates a structured THREAT_MODEL.md file from source code.
 * Inspired by Anthropic defending-code-reference-harness /threat-model skill.
 *
 * Output sections:
 * - System overview
 * - Trust boundaries
 * - Assets (data classification)
 * - Adversaries
 * - Attack surface
 * - Threats (STRIDE per trust boundary)
 * - Recommendations
 */

import type { ThreatModel } from '../triage/triage.js';

export interface ThreatModelOptions {
  projectName: string;
  language: 'php' | 'python' | 'javascript' | 'typescript';
  sourceFiles: Array<{ path: string; lines: number }>;
  entryPoints?: string[];
  knownUserInputs?: string[];
  dataStores?: string[];
}

export interface GeneratedThreatModel {
  projectName: string;
  trustBoundaries: string[];
  assets: Array<{ name: string; classification: string; location: string }>;
  adversaries: string[];
  attackSurfaces: string[];
  threats: Array<{
    id: string;
    stride: string;
    title: string;
    severity: string;
    boundary: string;
    description: string;
    mitigation: string;
  }>;
  recommendations: string[];
  markdown: string;
  json: ThreatModel;
}

export function generateThreatModel(options: ThreatModelOptions): GeneratedThreatModel {
  const trustBoundaries = inferTrustBoundaries(options);
  const assets = inferAssets(options);
  const adversaries = defaultAdversaries();
  const attackSurfaces = inferAttackSurfaces(options);
  const threats = inferThreats(options, trustBoundaries, assets);
  const recommendations = inferRecommendations(threats);

  const markdown = renderMarkdown(
    options,
    trustBoundaries,
    assets,
    adversaries,
    attackSurfaces,
    threats,
    recommendations
  );

  const json: ThreatModel = {
    internetFacing: attackSurfaces.filter(
      (s) => s.includes('api/') || s.includes('public/') || s.includes('upload/')
    ),
    internalOnly: attackSurfaces.filter((s) => s.includes('admin/') || s.includes('internal/')),
    dataClassification: Object.fromEntries(
      assets.map((a) => [
        a.location,
        a.classification as 'public' | 'internal' | 'confidential' | 'pii',
      ])
    ),
    criticalAssets: assets
      .filter((a) => a.classification === 'pii' || a.classification === 'confidential')
      .map((a) => a.location),
  };

  return {
    projectName: options.projectName,
    trustBoundaries,
    assets,
    adversaries,
    attackSurfaces,
    threats,
    recommendations,
    markdown,
    json,
  };
}

function inferTrustBoundaries(options: ThreatModelOptions): string[] {
  const boundaries: string[] = ['External user', 'Public API'];
  const hasDb = options.dataStores?.some(
    (d) =>
      d.includes('mysql') || d.includes('postgres') || d.includes('sqlite') || d.includes('mongo')
  );
  if (hasDb) boundaries.push('Database');
  const hasAuth = options.sourceFiles.some(
    (f) => f.path.includes('auth') || f.path.includes('login')
  );
  if (hasAuth) boundaries.push('Authentication');
  const hasAdmin = options.sourceFiles.some((f) => f.path.includes('admin'));
  if (hasAdmin) boundaries.push('Admin panel');
  if (options.knownUserInputs?.length) boundaries.push('Untrusted input');
  return boundaries;
}

function inferAssets(
  options: ThreatModelOptions
): Array<{ name: string; classification: string; location: string }> {
  const assets: Array<{ name: string; classification: string; location: string }> = [];
  if (options.sourceFiles.some((f) => f.path.includes('user') || f.path.includes('account'))) {
    assets.push({ name: 'User accounts', classification: 'pii', location: 'user' });
  }
  if (options.sourceFiles.some((f) => f.path.includes('payment') || f.path.includes('billing'))) {
    assets.push({ name: 'Payment data', classification: 'confidential', location: 'payment' });
  }
  if (
    options.dataStores?.some(
      (d) => d.toLowerCase().includes('mysql') || d.toLowerCase().includes('postgres')
    )
  ) {
    assets.push({ name: 'Database', classification: 'confidential', location: 'database' });
  }
  return assets;
}

function defaultAdversaries(): string[] {
  return [
    'External attacker (internet-facing APIs)',
    'Authenticated malicious user',
    'Insider with limited access',
    'Automated scanner/bot',
  ];
}

function inferAttackSurfaces(options: ThreatModelOptions): string[] {
  const surfaces = new Set<string>();
  for (const ep of options.entryPoints ?? []) surfaces.add(ep);
  for (const f of options.sourceFiles) {
    if (f.path.match(/\/(api|public|index)\.php|\/api\//)) surfaces.add(f.path);
  }
  if (surfaces.size === 0) surfaces.add('/');
  return Array.from(surfaces);
}

function inferThreats(
  options: ThreatModelOptions,
  boundaries: string[],
  assets: GeneratedThreatModel['assets']
): GeneratedThreatModel['threats'] {
  const threats: GeneratedThreatModel['threats'] = [];
  let id = 1;
  for (const surface of options.entryPoints ?? ['/']) {
    threats.push({
      id: `T${id++}`,
      stride: 'Tampering',
      title: `Untrusted input reaches ${surface} without validation`,
      severity: 'HIGH',
      boundary: 'External user → Public API',
      description: `Attacker sends malicious payload to ${surface}; downstream code trusts it.`,
      mitigation: 'Validate and sanitize all user input at the trust boundary.',
    });
  }
  if (assets.some((a) => a.classification === 'pii')) {
    threats.push({
      id: `T${id++}`,
      stride: 'Information Disclosure',
      title: 'PII may be exposed via error messages or logs',
      severity: 'HIGH',
      boundary: 'Application → Logs',
      description: 'Stack traces, debug info, or verbose errors leak user data.',
      mitigation: 'Sanitize error messages; disable debug mode in production.',
    });
  }
  if (options.sourceFiles.some((f) => f.path.includes('auth') || f.path.includes('login'))) {
    threats.push({
      id: `T${id++}`,
      stride: 'Spoofing',
      title: 'Weak authentication allows identity forgery',
      severity: 'CRITICAL',
      boundary: 'Authentication',
      description: 'Weak password hashing, missing MFA, or session fixation.',
      mitigation: 'Use password_hash with Argon2id; enforce MFA; rotate sessions.',
    });
  }
  return threats;
}

function inferRecommendations(threats: GeneratedThreatModel['threats']): string[] {
  const recs = new Set<string>();
  for (const t of threats) {
    if (t.severity === 'CRITICAL') recs.add(`Address CRITICAL threat: ${t.title}`);
  }
  recs.add('Run automated scanning (security-vule) on every commit');
  recs.add('Add SBOM generation and dependency review');
  recs.add('Enable rate limiting on auth endpoints');
  return Array.from(recs);
}

function renderMarkdown(
  options: ThreatModelOptions,
  boundaries: string[],
  assets: GeneratedThreatModel['assets'],
  adversaries: string[],
  surfaces: string[],
  threats: GeneratedThreatModel['threats'],
  recs: string[]
): string {
  const lines: string[] = [];
  lines.push(`# Threat Model: ${options.projectName}`);
  lines.push(``);
  lines.push(
    `_Generated by security-vule ${new Date().toISOString().slice(0, 10)} (Anthropic Harness-compatible)_`
  );
  lines.push(``);
  lines.push(`##1. System Overview`);
  lines.push(``);
  lines.push(`- **Project**: ${options.projectName}`);
  lines.push(`- **Language**: ${options.language}`);
  lines.push(
    `- **Source files**: ${options.sourceFiles.length} (${options.sourceFiles.reduce((s, f) => s + f.lines, 0)} LOC)`
  );
  lines.push(`- **Entry points**: ${surfaces.length}`);
  lines.push(`- **Data stores**: ${options.dataStores?.length ?? 0}`);
  lines.push(``);
  lines.push(`##2. Trust Boundaries`);
  lines.push(``);
  for (const b of boundaries) lines.push(`- ${b}`);
  lines.push(``);
  lines.push(`##3. Assets`);
  lines.push(``);
  for (const a of assets)
    lines.push(`- **${a.name}** (${a.classification}) — location: ${a.location}`);
  lines.push(``);
  lines.push(`##4. Adversaries`);
  lines.push(``);
  for (const a of adversaries) lines.push(`- ${a}`);
  lines.push(``);
  lines.push(`##5. Attack Surface`);
  lines.push(``);
  for (const s of surfaces) lines.push(`- \`${s}\``);
  lines.push(``);
  lines.push(`##6. Threats (STRIDE per boundary)`);
  lines.push(``);
  lines.push(`| ID | STRIDE | Title | Severity | Boundary |`);
  lines.push(`|----|--------|-------|----------|----------|`);
  for (const t of threats)
    lines.push(`| ${t.id} | ${t.stride} | ${t.title} | ${t.severity} | ${t.boundary} |`);
  lines.push(``);
  lines.push(`##7. Recommendations`);
  lines.push(``);
  for (const r of recs) lines.push(`- ${r}`);
  lines.push(``);
  return lines.join('\n');
}

/**
 * STRIDE threat model — categorize findings by threat class.
 * Maps detected vulnerability types to STRIDE categories for threat modeling reports.
 */

export type StrideCategory = 'S' | 'T' | 'R' | 'I' | 'D' | 'E';

export const STRIDE_FULL_NAME: Record<StrideCategory, string> = {
  S: 'Spoofing',
  T: 'Tampering',
  R: 'Repudiation',
  I: 'Information Disclosure',
  D: 'Denial of Service',
  E: 'Elevation of Privilege',
};

const TYPE_TO_STRIDE: Record<string, StrideCategory[]> = {
  sql: ['T', 'I'],
  nosql: ['T', 'I'],
  shell: ['T', 'E'],
  xss: ['T'],
  ssrf: ['I', 'E'],
  file_include: ['I', 'E'],
  file_write: ['T', 'E'],
  crypto: ['I'],
  hash: ['I'],
  weakrand: ['S'],
  ldap: ['T', 'I', 'E'],
  xpath: ['T', 'I'],
  xxe: ['I'],
  deserialization: ['T', 'E'],
  eval: ['T', 'E'],
  dynamic_code: ['T', 'E'],
  network_send: ['I'],
  trustbound: ['E'],
  securecookie: ['S', 'I'],
};

export function categorizeByStride(vulnType: string): StrideCategory[] {
  return TYPE_TO_STRIDE[vulnType] ?? ['T'];
}

export interface ThreatEntry {
  stride: StrideCategory;
  strideName: string;
  threat: string;
  cwe: string;
  sourceFile: string;
  sourceLine: number;
  confidence: number;
  severity: string;
}

export interface ThreatModel {
  target: string;
  totalThreats: number;
  byStride: Record<StrideCategory, number>;
  threats: ThreatEntry[];
  generatedAt: string;
}

export function buildThreatModel(
  target: string,
  findings: Array<{ type: string; cwe?: string; file: string; line: number; confidence: number; severity: string }>
): ThreatModel {
  const threats: ThreatEntry[] = [];
  const byStride: Record<StrideCategory, number> = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
  for (const f of findings) {
    const strides = categorizeByStride(f.type);
    for (const s of strides) {
      threats.push({
        stride: s,
        strideName: STRIDE_FULL_NAME[s],
        threat: `${s} via ${f.type} (${STRIDE_FULL_NAME[s]})`,
        cwe: f.cwe ?? 'unknown',
        sourceFile: f.file,
        sourceLine: f.line,
        confidence: f.confidence,
        severity: f.severity,
      });
      byStride[s]++;
    }
  }
  return {
    target,
    totalThreats: threats.length,
    byStride,
    threats,
    generatedAt: new Date().toISOString(),
  };
}

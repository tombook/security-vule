import type { STRIDECategory } from './types.js';
import type { TaintSource, TaintSink } from '../engine/taint.js';

export interface STRIDEMapping {
  category: STRIDECategory;
  sourceType: TaintSource['type'];
  sinkType: TaintSink['type'];
  cweIds: string[];
  owasp: string;
  rulePrefixes: string[];
}

export const STRIDE_MAPPINGS: STRIDEMapping[] = [
  // Tampering — untrusted input modifies protected data
  { category: 'tampering', sourceType: 'user_input', sinkType: 'sql', cweIds: ['CWE-89'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'user_input', sinkType: 'shell', cweIds: ['CWE-78'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'user_input', sinkType: 'eval', cweIds: ['CWE-94'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'user_input', sinkType: 'file_write', cweIds: ['CWE-22', 'CWE-49'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'user_input', sinkType: 'dynamic_code', cweIds: ['CWE-94'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'network', sinkType: 'sql', cweIds: ['CWE-89'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'network', sinkType: 'shell', cweIds: ['CWE-78'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },
  { category: 'tampering', sourceType: 'network', sinkType: 'eval', cweIds: ['CWE-94'], owasp: 'A03:2021', rulePrefixes: ['INJ'] },

  // Spoofing — untrusted input impersonates identity
  { category: 'spoofing', sourceType: 'cookie', sinkType: 'sql', cweIds: ['CWE-287', 'CWE-384'], owasp: 'A07:2021', rulePrefixes: ['AUTH'] },
  { category: 'spoofing', sourceType: 'header', sinkType: 'sql', cweIds: ['CWE-287', 'CWE-613'], owasp: 'A07:2021', rulePrefixes: ['AUTH'] },
  { category: 'spoofing', sourceType: 'network', sinkType: 'eval', cweIds: ['CWE-94', 'CWE-287'], owasp: 'A07:2021', rulePrefixes: ['INJ', 'AUTH'] },

  // Repudiation — actions cannot be attributed
  { category: 'repudiation', sourceType: 'cookie', sinkType: 'sql', cweIds: ['CWE-778'], owasp: 'A09:2021', rulePrefixes: ['AUTH'] },
  { category: 'repudiation', sourceType: 'header', sinkType: 'sql', cweIds: ['CWE-778', 'CWE-295'], owasp: 'A09:2021', rulePrefixes: ['AUTH'] },

  // Information Disclosure — sensitive data exposed
  { category: 'information_disclosure', sourceType: 'user_input', sinkType: 'network_send', cweIds: ['CWE-201', 'CWE-352'], owasp: 'A01:2021', rulePrefixes: ['INJ'] },
  { category: 'information_disclosure', sourceType: 'db', sinkType: 'network_send', cweIds: ['CWE-200', 'CWE-532'], owasp: 'A01:2021', rulePrefixes: ['CRYPTO'] },
  { category: 'information_disclosure', sourceType: 'file_io', sinkType: 'network_send', cweIds: ['CWE-200', 'CWE-532'], owasp: 'A01:2021', rulePrefixes: ['CRYPTO'] },
  { category: 'information_disclosure', sourceType: 'env', sinkType: 'network_send', cweIds: ['CWE-200', 'CWE-532'], owasp: 'A01:2021', rulePrefixes: ['CRYPTO'] },
  { category: 'information_disclosure', sourceType: 'cookie', sinkType: 'network_send', cweIds: ['CWE-532'], owasp: 'A01:2021', rulePrefixes: ['CRYPTO'] },

  // Denial of Service — resource exhaustion
  { category: 'denial_of_service', sourceType: 'user_input', sinkType: 'eval', cweIds: ['CWE-400', 'CWE-770'], owasp: 'A05:2021', rulePrefixes: ['INJ'] },
  { category: 'denial_of_service', sourceType: 'user_input', sinkType: 'file_write', cweIds: ['CWE-400', 'CWE-789'], owasp: 'A05:2021', rulePrefixes: ['INJ', 'MEM'] },
  { category: 'denial_of_service', sourceType: 'network', sinkType: 'eval', cweIds: ['CWE-400'], owasp: 'A05:2021', rulePrefixes: ['INJ'] },

  // Elevation of Privilege — gaining unauthorized access
  { category: 'elevation_of_privilege', sourceType: 'user_input', sinkType: 'shell', cweIds: ['CWE-78', 'CWE-269'], owasp: 'A01:2021', rulePrefixes: ['INJ', 'AUTH'] },
  { category: 'elevation_of_privilege', sourceType: 'env', sinkType: 'shell', cweIds: ['CWE-78', 'CWE-862'], owasp: 'A01:2021', rulePrefixes: ['INJ', 'AUTH'] },
  { category: 'elevation_of_privilege', sourceType: 'network', sinkType: 'shell', cweIds: ['CWE-78'], owasp: 'A01:2021', rulePrefixes: ['INJ', 'AUTH'] },
  { category: 'elevation_of_privilege', sourceType: 'user_input', sinkType: 'eval', cweIds: ['CWE-94', 'CWE-269'], owasp: 'A01:2021', rulePrefixes: ['INJ', 'AUTH'] },
  { category: 'elevation_of_privilege', sourceType: 'user_input', sinkType: 'deserialization', cweIds: ['CWE-502'], owasp: 'A08:2021', rulePrefixes: ['INJ'] },
];

export function classifySourceSink(
  sourceType: TaintSource['type'],
  sinkType: TaintSink['type'],
): STRIDEMapping[] {
  return STRIDE_MAPPINGS.filter(
    m => m.sourceType === sourceType && m.sinkType === sinkType,
  );
}

export function getCategoriesForSourceSink(
  sourceType: TaintSource['type'],
  sinkType: TaintSink['type'],
): STRIDECategory[] {
  const categories = new Set<STRIDECategory>();
  for (const mapping of STRIDE_MAPPINGS) {
    if (mapping.sourceType === sourceType && mapping.sinkType === sinkType) {
      categories.add(mapping.category);
    }
  }
  return Array.from(categories);
}

export function computeThreatPriority(
  category: STRIDECategory,
  confidence: number,
  hasSanitizer: boolean,
): number {
  const categoryWeights: Record<STRIDECategory, number> = {
    tampering: 90,
    elevation_of_privilege: 85,
    spoofing: 75,
    information_disclosure: 70,
    denial_of_service: 55,
    repudiation: 45,
  };

  const base = categoryWeights[category] ?? 50;
  const sanitizerPenalty = hasSanitizer ? -30 : 0;
  const confidenceScale = confidence;
  return Math.round(Math.max(0, Math.min(100, (base + sanitizerPenalty) * confidenceScale)));
}

export function mapBoundaryType(
  sourceType: TaintSource['type'],
  sinkType: TaintSink['type'],
): 'input' | 'output' | 'data_store' | 'process' | 'network' {
  if (['network', 'header', 'cookie'].includes(sourceType)) return 'network';
  if (['db', 'file_io'].includes(sourceType)) return 'data_store';
  if (['sql', 'db'].includes(sinkType)) return 'data_store';
  if (['network_send'].includes(sinkType)) return 'output';
  if (['shell', 'eval', 'dynamic_code'].includes(sinkType)) return 'process';
  return 'input';
}

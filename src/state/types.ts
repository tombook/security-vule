export const STATE_STATUSES = [
  'open',
  'confirmed',
  'fixed',
  'wontfix',
  'false_positive',
] as const;

export type FindingStatus = typeof STATE_STATUSES[number];

export function isFindingStatus(value: string): value is FindingStatus {
  return (STATE_STATUSES as readonly string[]).includes(value);
}

export interface FindingStateEntry {
  status: FindingStatus;
  note?: string;
  by: string;
  at: string;
}

export interface StateFile {
  version: number;
  updated_at: string;
  fingerprints: Record<string, FindingStateEntry>;
}

export const STATE_FILE_VERSION = 1;
export const DEFAULT_STATE_FILENAME = '.vule-state.json';

export interface FingerprintParts {
  file: string;
  line: number;
  type: string;
}

export function isStateFile(x: unknown): x is StateFile {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const obj = x as Record<string, unknown>;
  if (typeof obj.version !== 'number') return false;
  if (typeof obj.updated_at !== 'string') return false;
  if (!obj.fingerprints || typeof obj.fingerprints !== 'object' || Array.isArray(obj.fingerprints)) return false;
  for (const entry of Object.values(obj.fingerprints as Record<string, unknown>)) {
    if (!isFindingStateEntry(entry)) return false;
  }
  return true;
}

export function isFindingStateEntry(x: unknown): x is FindingStateEntry {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const e = x as Record<string, unknown>;
  if (!isFindingStatus(e.status as string)) return false;
  if (typeof e.by !== 'string') return false;
  if (typeof e.at !== 'string') return false;
  if (e.note !== undefined && typeof e.note !== 'string') return false;
  return true;
}

export function fingerprintOf(parts: FingerprintParts): string {
  return `${parts.file}:${parts.line}:${parts.type}`;
}

export function defaultAuthor(): string {
  return process.env.USER || process.env.USERNAME || 'unknown';
}

export function emptyState(): StateFile {
  return {
    version: STATE_FILE_VERSION,
    updated_at: new Date().toISOString(),
    fingerprints: {},
  };
}
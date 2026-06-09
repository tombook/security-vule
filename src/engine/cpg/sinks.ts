/**
 * Sink function lookup tables (per language).
 * Sinks are dangerous functions that should NOT receive untrusted data.
 * Used by CPGBuilder.sinkNodes() and dimension #1 (引力场).
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { CPGLanguage } from './types.js';

export interface SinkConfig {
  [category: string]: string[];
}

export type SinksByLanguage = Record<CPGLanguage, SinkConfig>;

let _cached: SinksByLanguage | null = null;

function loadConfig(): SinksByLanguage {
  if (_cached) return _cached;
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const configPath = join(__dirname, '../../../config/cpg-sinks.yaml');
  if (!existsSync(configPath)) {
    _cached = { php: {}, python: {}, javascript: {}, typescript: {} } as SinksByLanguage;
    return _cached;
  }
  const text = readFileSync(configPath, 'utf-8');
  const result: any = {};
  let currentLang: string | null = null;
  let currentCat: string | null = null;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '');
    if (!line.trim()) continue;
    const langMatch = line.match(/^(\w+):\s*$/);
    const catMatch = line.match(/^\s{2}(\w+):\s*$/);
    const itemMatch = line.match(/^\s{4}-\s*(\S+)/);
    if (langMatch) { currentLang = langMatch[1]; result[currentLang] = {}; }
    else if (catMatch && currentLang) { currentCat = catMatch[1]; result[currentLang][currentCat] = []; }
    else if (itemMatch && currentLang && currentCat) { result[currentLang][currentCat].push(itemMatch[1]); }
  }
  _cached = result as SinksByLanguage;
  return _cached;
}

export function isSinkFunction(funcName: string, language: CPGLanguage): boolean {
  const cfg = loadConfig()[language];
  if (!cfg) return false;
  for (const cat of Object.values(cfg)) {
    if (cat.includes(funcName)) return true;
  }
  return false;
}

export function getSinks(language: CPGLanguage): SinkConfig {
  return loadConfig()[language] || {};
}
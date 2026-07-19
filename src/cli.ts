#!/usr/bin/env bun
/**
 * security-vule CLI — single-file entry point for scanning, reporting, and CI integration.
 *
 * Subcommands:
 *   scan <path>           Run static analysis on a directory or file
 *   scan --sarif          Emit SARIF 2.1.0 output for GitHub Code Scanning
 *   scan --baseline FILE  Skip findings already in baseline (incremental CI)
 *   scan --diff           Only show new findings since baseline
 *   poc-verify           Run runtime PoC verification
 *   version              Print version
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, relative, extname } from 'path';
import { analyzeFile, type AnalysisResult, type VulnerabilityFinding } from './engine/analyzer.js';
import { runSCA, combineFindings, type SCAFinding } from './sca/index.js';
import { stateCommand, stateHelp } from './state/cli.js';
import { StateManager } from './state/manager.js';
import { DEFAULT_STATE_FILENAME, isFindingStatus, STATE_STATUSES, type FindingStatus } from './state/types.js';
import { fingerprintOf as fingerprintOfParts } from './state/types.js';
import { createWatcher } from './scan/watcher.js';

const SUPPORTED_EXT = new Set(['.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.go', '.rs', '.php', '.phtml']);

import {
  runPoCVerification,
  isPoCTarget,
  type PoCTarget,
  type MergedFinding,
} from './poc/runner.js';
import { generatePocForFinding } from './poc/generator.js';
import { createDefaultRouter, type LLMRouter } from './llm/router.js';
import { UsageStore } from './usage/store.js';
import { USAGE_FILENAME } from './usage/types.js';
import { generateReport, formatMarkdown, parseTimeArg, type GroupBy, type ReportFormat } from './usage/reporter.js';
import { AuditLogger, GLOBAL_AUDIT_LOGGER } from './audit/logger.js';

export interface ScanArgs {
  target: string;
  outputFile?: string;
  sarifMode: boolean;
  baselineFile?: string;
  diffMode: boolean;
  minConfidence: number;
  scaList: string[];
  statusFilter: FindingStatus[];
  stateFile?: string;
  withPoc: boolean;
  pocTarget: PoCTarget;
  pocAutoConfirm: boolean;
  watch: boolean;
  debounceMs: number;
  pollInterval: number;
}

export const DEFAULT_STATUS_FILTER: FindingStatus[] = ['open', 'confirmed'];
export const DEFAULT_POC_TARGET: PoCTarget = 'none';

export function parseScanArgs(args: string[]): ScanArgs | { error: string } {
  const target = args[0];
  if (!target) return { error: 'missing target' };
  let outputFile: string | undefined;
  let sarifMode = false;
  let baselineFile: string | undefined;
  let diffMode = false;
  let minConfidence = 0;
  let scaList: string[] = [];
  let statusArgs: string[] = [];
  let stateFile: string | undefined;
  let withPoc = false;
  let pocTarget: PoCTarget = DEFAULT_POC_TARGET;
  let pocAutoConfirm = false;
  let watch = false;
  let debounceMs = 300;
  let pollInterval = 200;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--sarif') sarifMode = true;
    else if (a === '--with-poc') withPoc = true;
    else if (a === '--poc-auto-confirm') pocAutoConfirm = true;
    else if (a === '--watch') watch = true;
    else if (a === '--baseline') { baselineFile = args[++i]; }
    else if (a === '--diff') diffMode = true;
    else if (a === '--output' || a === '-o') { outputFile = args[++i]; }
    else if (a === '--min-confidence') { minConfidence = Number(args[++i]); }
    else if (a === '--state-file') { stateFile = args[++i]; }
    else if (a.startsWith('--status=')) statusArgs.push(a.slice('--status='.length));
    else if (a === '--status') { statusArgs.push(args[++i] ?? ''); }
    else if (a.startsWith('--sca=')) scaList = a.slice('--sca='.length).split(',').map(s => s.trim()).filter(Boolean);
    else if (a.startsWith('--poc-target=')) {
      const v = a.slice('--poc-target='.length);
      if (!isPoCTarget(v)) return { error: `invalid --poc-target value: ${v}` };
      pocTarget = v;
    }
    else if (a.startsWith('--debounce=')) {
      const v = Number(a.slice('--debounce='.length));
      if (!isNaN(v) && v >= 0) debounceMs = v;
    }
    else if (a === '--debounce') {
      const v = Number(args[++i]);
      if (!isNaN(v) && v >= 0) debounceMs = v;
    }
    else if (a.startsWith('--poll-interval=')) {
      const v = Number(a.slice('--poll-interval='.length));
      if (!isNaN(v) && v >= 0) pollInterval = v;
    }
    else if (a === '--poll-interval') {
      const v = Number(args[++i]);
      if (!isNaN(v) && v >= 0) pollInterval = v;
    }
  }
  let statusFilter: FindingStatus[];
  if (statusArgs.length === 0) {
    statusFilter = [...DEFAULT_STATUS_FILTER];
  } else {
    const parts = statusArgs.flatMap(s => s.split(',').map(x => x.trim()).filter(Boolean));
    const invalid = parts.filter(p => !isFindingStatus(p));
    if (invalid.length > 0) return { error: `invalid --status value(s): ${invalid.join(',')}` };
    statusFilter = [...new Set(parts as FindingStatus[])];
    if (statusFilter.length === 0) statusFilter = [...DEFAULT_STATUS_FILTER];
  }
  return { target, outputFile, sarifMode, baselineFile, diffMode, minConfidence, scaList, statusFilter, stateFile, withPoc, pocTarget, pocAutoConfirm, watch, debounceMs, pollInterval };
}

function walkFiles(root: string): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let stat: any;
    try { stat = require('fs').statSync(cur); } catch { continue; }
    if (stat.isDirectory()) {
      const entries = require('fs').readdirSync(cur);
      for (const e of entries) {
        if (e === 'node_modules' || e === '.git' || e === 'dist' || e === 'build' || e === 'vendor') continue;
        stack.push(join(cur, e));
      }
    } else if (stat.isFile()) {
      const ext = extname(cur);
      if (SUPPORTED_EXT.has(ext)) out.push(cur);
    }
  }
  return out;
}

function loadBaseline(path: string | undefined, scanRoot: string): Set<string> {
  if (!path || !existsSync(path)) return new Set();
  const data = JSON.parse(readFileSync(path, 'utf-8'));
  const findings = Array.isArray(data) ? data : (data.findings || []);
  return new Set(findings.map((f: any) => `${relative(scanRoot, f.file)}:${f.line}:${f.type}`));
}

function resolveStateFile(stateFile: string | undefined, target: string): string {
  if (stateFile) return stateFile;
  return require('path').join(target, DEFAULT_STATE_FILENAME);
}

async function loadStateMap(stateFile: string | undefined, target: string): Promise<Map<string, FindingStatus>> {
  const path = resolveStateFile(stateFile, target);
  const mgr = new StateManager(path);
  const all = await mgr.getAll();
  const out = new Map<string, FindingStatus>();
  for (const [fp, entry] of Object.entries(all)) out.set(fp, entry.status);
  return out;
}

function severitySummary(findings: { severity: string }[]): { critical: number; high: number; medium: number; low: number; by_severity: Record<string, number> } {
  let critical = 0, high = 0, medium = 0, low = 0;
  for (const f of findings) {
    const s = (f.severity || '').toUpperCase();
    if (s === 'CRITICAL') critical++;
    else if (s === 'HIGH') high++;
    else if (s === 'MEDIUM') medium++;
    else low++;
  }
  return {
    critical, high, medium, low,
    by_severity: { critical, high, medium, low },
  };
}

function generateSeverityPie(sev: { critical: number; high: number; medium: number; low: number }): string {
  return `pie title 漏洞严重程度分布
    "Critical" : ${sev.critical}
    "High" : ${sev.high}
    "Medium" : ${sev.medium}
    "Low" : ${sev.low}`;
}

function generatePocPie(poc: { verified: number; unverified: number; unconfirmed: number }): string {
  return `pie title PoC 验证状态分布
    "Verified" : ${poc.verified}
    "Not Exploited" : ${poc.unverified}
    "Unconfirmed" : ${poc.unconfirmed}`;
}

function triageSummary(state: Map<string, FindingStatus>, findings: { file: string; line: number; type: string }[], scanRoot: string): Record<FindingStatus, number> {
  const counts: Record<FindingStatus, number> = {
    open: 0, confirmed: 0, fixed: 0, wontfix: 0, false_positive: 0,
  };
  for (const f of findings) {
    const fp = fingerprintOfParts({ file: relative(scanRoot, f.file), line: f.line, type: f.type });
    const status = state.get(fp) ?? 'open';
    counts[status]++;
  }
  return counts;
}

function formatTriageHeader(counts: Record<FindingStatus, number>): string {
  return `Open: ${counts.open} · Confirmed: ${counts.confirmed} · Fixed: ${counts.fixed} · WontFix: ${counts.wontfix} · FP: ${counts.false_positive}`;
}

function toSarif(findings: VulnerabilityFinding[], targetPath: string, options: { stripSnippets?: boolean; stateMap?: Map<string, FindingStatus> } = {}): unknown {
  const stripSnippets = options.stripSnippets !== false;
  const rules = new Map<string, any>();
  const results: any[] = [];
  for (const f of findings) {
    const ruleId = `sv-${f.type}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.type,
        shortDescription: { text: stripSnippets ? `${f.type} vulnerability detected` : `${f.type} vulnerability detected` },
        fullDescription: { text: stripSnippets ? sanitizeSarifMessage(f.description) : f.description },
        helpUri: 'https://github.com/security-vule/security-vule',
        defaultConfiguration: { level: severityToSarifLevel(f.severity) },
        properties: stripSnippets ? { cwe: f.cwe, tags: ['security', 'vulnerability'], confidence: f.confidence } : { cwe: f.cwe, tags: ['security', 'vulnerability'] },
      });
    }
    const messageText = stripSnippets ? sanitizeSarifMessage(f.description) : (f.description || `${f.type} vulnerability`);
    const result: any = {
      ruleId,
      level: severityToSarifLevel(f.severity),
      message: { text: messageText },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: relative(process.cwd(), f.file) || f.file },
          region: { startLine: f.line, startColumn: 1 },
        },
      }],
      partialFingerprints: [`${relative(process.cwd(), f.file)}:${f.line}:${f.type}`],
    };
    if (!stripSnippets) {
      result.properties = { confidence: f.confidence, cwe: f.cwe };
    } else {
      result.properties = { confidence: f.confidence, cwe: f.cwe, codeStripped: true };
    }
    const fp = `${relative(targetPath, f.file)}:${f.line}:${f.type}`;
    if (options.stateMap && options.stateMap.has(fp)) {
      result.properties.triageState = options.stateMap.get(fp);
    }
    results.push(result);
  }
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
  runs: [{
      tool: {
        driver: {
          name: 'security-vule',
          informationUri: 'https://github.com/security-vule/security-vule',
          semanticVersion: '0.1.0',
          rules: Array.from(rules.values()),
        },
      },
      originalUriBaseIds: { PROJECTROOT: { uri: `file://${process.cwd()}/` } },
      results,
      properties: {
        'security-vule/sarif-sanitized': String(stripSnippets),
        'security-vule/ai-security-version': '1.0.0',
      },
    }],
  };
}

const CODE_LIKE_PATTERNS = [
  /```[\s\S]*?```/g,
  /`[^`]{30,}`/g,
  /\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*?\]/g,
];

function sanitizeSarifMessage(text: string): string {
  if (!text) return text;
  let s = text;
  for (const p of CODE_LIKE_PATTERNS) s = s.replace(p, '[code-stripped]');
  if (s.length > 500) s = s.slice(0, 500) + '...';
  return s;
}

function severityToSarifLevel(sev: string): string {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'medium') return 'warning';
  return 'note';
}

interface ScanResult {
  combined: (VulnerabilityFinding & { source: string; exploit_proven?: boolean | null; poc_mark?: string })[];
  visible: (VulnerabilityFinding & { source: string; exploit_proven?: boolean | null; poc_mark?: string })[];
  counts: Record<FindingStatus, number>;
  pocSummary: { verified: number; unverified: number; unconfirmed: number; mode: string; target: string } | null;
  filesScanned: number;
  stateMap: Map<string, FindingStatus>;
}

async function performScan(
  files: string[],
  abs: string,
  target: string,
  options: {
    minConfidence: number;
    scaList: string[];
    withPoc: boolean;
    pocTarget: PoCTarget;
    pocAutoConfirm: boolean;
    stateFile?: string;
    statusFilter: FindingStatus[];
    baselineFile?: string;
    diffMode: boolean;
  },
  deps?: { runner?: SpawnRunner; probe?: PortProbe }
): Promise<ScanResult> {
  const { minConfidence, scaList, withPoc, pocTarget, pocAutoConfirm, stateFile, statusFilter, baselineFile, diffMode } = options;

  const dfgFindings: VulnerabilityFinding[] = [];
  for (const f of files) {
    let result: AnalysisResult;
    try {
      const src = readFileSync(f, 'utf-8');
      result = await analyzeFile(f, src);
    } catch (e) { console.error(`[skip] ${f}: ${(e as Error).message}`); continue; }
    for (const finding of result.vulnerabilities) {
      if (finding.confidence >= minConfidence) dfgFindings.push(finding);
    }
  }
  let scaFindings: SCAFinding[] = [];
  if (scaList.length > 0) {
    console.error(`[security-vule] running SCA: ${scaList.join(', ')}`);
    const r = await runSCA(abs, scaList);
    scaFindings = r.findings;
    if (r.skipped.length > 0) {
      console.error(`[security-vule] SCA skipped: ${r.skipped.map(s => `${s.name}(${s.reason})`).join(', ')}`);
    }
  }
  const dfgAnnotated: (VulnerabilityFinding & { source: string })[] = dfgFindings.map(f => ({ ...f, source: 'sv-dfg' }));
  let combined: (VulnerabilityFinding & { source: string; exploit_proven?: boolean | null; poc_mark?: string })[] =
    combineFindings(dfgAnnotated, scaFindings) as (VulnerabilityFinding & { source: string })[];
  let pocSummary: { verified: number; unverified: number; unconfirmed: number; mode: string; target: string } | null = null;
  if (withPoc && pocTarget !== 'none') {
    console.error(`[security-vule] running PoC verification (target=${pocTarget})`);
    const r = await runPoCVerification(combined, { target: pocTarget, runner: deps?.runner, probe: deps?.probe });
    if (!r.ok) {
      console.error(`[security-vule/poc] ${r.message ?? 'verification skipped'}`);
    } else if (r.merged && r.verification) {
      const mergedMap = new Map<string, MergedFinding>();
      for (const m of r.merged) {
        const k = `${relative(abs, m.file)}:${m.line}:${m.type}`;
        mergedMap.set(k, m);
      }
      combined = combined.map((f) => {
        const k = `${relative(abs, f.file)}:${f.line}:${f.type}`;
        const m = mergedMap.get(k);
        if (m) {
          return { ...f, exploit_proven: m.exploit_proven, poc_mark: m.poc_mark };
        }
        return { ...f, exploit_proven: null, poc_mark: '⚠️ not verified' };
      });
      pocSummary = {
        verified: r.verification.verified,
        unverified: r.verification.unverified,
        unconfirmed: r.verification.unconfirmed,
        mode: r.verification.mode,
        target: r.verification.target,
      };
      console.error(`[security-vule/poc] ${pocSummary.verified} verified, ${pocSummary.unverified} not exploited, ${pocSummary.unconfirmed} unconfirmed`);
      if (pocAutoConfirm) {
        const stateFilePath = resolveStateFile(stateFile, abs);
        const mgr = new StateManager(stateFilePath);
        let confirmedCount = 0;
        for (const m of r.merged) {
          if (m.exploit_proven === true) {
            const fp = fingerprintOfParts({ file: relative(abs, m.file), line: m.line, type: m.type });
            await mgr.setStatus(fp, 'confirmed', 'PoC verified');
            confirmedCount++;
          }
        }
        console.error(`[security-vule/poc] auto-confirmed ${confirmedCount} findings via state manager`);
      }
    }
  }
  const baseline = loadBaseline(baselineFile, abs);
  let stateMap = await loadStateMap(stateFile, abs);
  if (withPoc && pocAutoConfirm) {
    stateMap = await loadStateMap(stateFile, abs);
  }
  const allowed = new Set<FindingStatus>(statusFilter);
  const allAfterStatus = combined.filter(f => {
    const fp = fingerprintOfParts({ file: relative(abs, f.file), line: f.line, type: f.type });
    const status = stateMap.get(fp) ?? 'open';
    return allowed.has(status);
  });
  const counts = triageSummary(stateMap, combined, abs);
  let visible = allAfterStatus;
  if (diffMode) {
    visible = visible.filter(f => !baseline.has(`${relative(abs, f.file)}:${f.line}:${f.type}`));
  }

  return { combined, visible, counts, pocSummary, filesScanned: files.length, stateMap };
}

function outputScanResult(
  result: ScanResult,
  target: string,
  abs: string,
  options: {
    sarifMode: boolean;
    outputFile?: string;
    diffMode: boolean;
    baselineFile?: string;
  }
): void {
  const { combined, visible, counts, pocSummary, filesScanned, stateMap } = result;
  const { sarifMode, outputFile } = options;

  console.error(formatTriageHeader(counts));

  if (sarifMode) {
    const out = toSarif(visible, abs, { stripSnippets: true, stateMap });
    const json = JSON.stringify(out, null, 2);
    if (outputFile) { writeFileSync(outputFile, json); console.error(`[security-vule] SARIF written to ${outputFile}`); }
    else process.stdout.write(json);
  } else {
    const sev = severitySummary(combined);
    const pocVerified = pocSummary?.verified ?? 0;
    const pocNotExploited = pocSummary?.unverified ?? 0;
    const summary: any = {
      summary: {
        total_findings: combined.length,
        critical: sev.critical,
        high: sev.high,
        medium: sev.medium,
        low: sev.low,
        by_severity: sev.by_severity,
        poc_verified: pocVerified,
        poc_not_exploited: pocNotExploited,
        files_scanned: filesScanned,
      },
      mermaid: {
        severity_pie: generateSeverityPie(sev),
      },
      target,
      files_scanned: filesScanned,
      total_findings: combined.length,
      shown_findings: visible.length,
      triage: counts,
      findings: visible,
    };
    if (pocSummary) {
      summary.poc = pocSummary;
      summary.mermaid.poc_pie = generatePocPie(pocSummary);
    }
    if (outputFile) { writeFileSync(outputFile, JSON.stringify(summary, null, 2)); console.error(`[security-vule] written to ${outputFile}`); }
    else console.log(JSON.stringify(summary, null, 2));
  }
  console.error(`[security-vule] ${combined.length} findings, ${visible.length} shown`);
}

export async function scanCommand(args: string[], deps?: { runner?: SpawnRunner; probe?: PortProbe }): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`scan <path>            Static analysis scan
  --sarif                SARIF 2.1.0 output
  --baseline FILE        Skip findings already in baseline
  --diff                 Only show new findings since baseline
  --output FILE | -o F   Write to file instead of stdout
  --min-confidence N     Filter by confidence (0..1)
  --status=LIST          Triage statuses to show (default: open,confirmed)
  --state-file F         Use F instead of <target>/.vule-state.json
  --sca=semgrep,trivy    Run external SCA tools (opt-in)
  --with-poc             Run verify-poc after scan and merge results
  --poc-target=mock|real|none  Target for PoC verification (default: none)
  --poc-auto-confirm     Auto-set state=confirmed for PoC-proven findings
  --watch                Watch mode: scan on file changes
  --debounce=MS          Debounce time for watch mode (default: 300)
  --poll-interval=MS     Poll interval (reserved, default: 200)
  --help | -h            Show this help`);
    return 0;
  }
  const parsed = parseScanArgs(args);
  if ('error' in parsed) {
    console.error('Usage: security-vule scan <path> [--sarif] [--baseline FILE] [--diff] [--output FILE] [--status=open,confirmed] [--state-file FILE] [--sca=semgrep,trivy] [--with-poc] [--poc-target=mock|real|none] [--poc-auto-confirm] [--watch] [--debounce=MS]');
    return 2;
  }
  const { target, outputFile, sarifMode, baselineFile, diffMode, minConfidence, scaList, statusFilter, stateFile, withPoc, pocTarget, pocAutoConfirm, watch, debounceMs, pollInterval } = parsed;
  if (pocAutoConfirm && !withPoc) {
    console.error('[security-vule] --poc-auto-confirm requires --with-poc');
    return 2;
  }
  const abs = require('path').resolve(target);
  if (!existsSync(abs)) {
    console.error(`Path not found: ${target}`);
    return 2;
  }

  const scanOptions = {
    minConfidence,
    scaList,
    withPoc,
    pocTarget,
    pocAutoConfirm,
    stateFile,
    statusFilter,
    baselineFile,
    diffMode,
  };

  const outputOptions = {
    sarifMode,
    outputFile,
    diffMode,
    baselineFile,
  };

  if (!watch) {
    const files = walkFiles(abs);
    console.error(`[security-vule] scanning ${files.length} files in ${target}`);

    try {
      GLOBAL_AUDIT_LOGGER.log({
        action: 'scan.started',
        target: target,
        result: 'ok',
        meta: { files_count: files.length },
      });
    } catch (e) {
      console.warn(`[audit] scan.started log failed: ${(e as Error).message}`);
    }

    const result = await performScan(files, abs, target, scanOptions, deps);
    outputScanResult(result, target, abs, outputOptions);

    try {
      GLOBAL_AUDIT_LOGGER.log({
        action: 'scan.completed',
        target: target,
        result: 'ok',
        meta: { findings_count: result.combined.length, files_scanned: files.length },
      });
    } catch (e) {
      console.warn(`[audit] scan.completed log failed: ${(e as Error).message}`);
    }

    return result.visible.some(f => f.severity === 'CRITICAL') ? 1 : 0;
  }

  const files = walkFiles(abs);
  console.error(`[security-vule] scanning ${files.length} files in ${target} (watch mode)`);
  console.error(`[security-vule] watch mode: debounce=${debounceMs}ms`);

  let result = await performScan(files, abs, target, scanOptions, deps);
  outputScanResult(result, target, abs, outputOptions);
  console.error(`[security-vule] watching for changes... (Ctrl+C to exit)`);

  const extensions = Array.from(SUPPORTED_EXT);
  const watcher = createWatcher({
    root: abs,
    extensions,
    debounceMs,
    pollInterval,
    onChange: async (changedFiles) => {
      const validFiles = changedFiles.filter(f => existsSync(f));
      if (validFiles.length === 0) return;

      console.error(`\n[security-vule] ${changedFiles.length} file(s) changed, rescanning...`);

      const incrementalResult = await performScan(validFiles, abs, target, scanOptions, deps);

      const prevCount = result.combined.length;
      result = incrementalResult;

      const newCount = result.combined.length;
      const diff = newCount - prevCount;

      console.error(`[security-vule] incremental scan complete: ${validFiles.length} file(s) scanned`);
      console.error(formatTriageHeader(result.counts));
      console.error(`[security-vule] ${result.combined.length} total findings (${diff >= 0 ? '+' : ''}${diff} since last)`);
    },
    onReady: () => {
      console.error(`[security-vule] file watcher ready`);
    },
  });

  await watcher.start();

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`\n[security-vule] shutting down watcher...`);
    await watcher.stop();
    console.error(`[security-vule] watcher stopped`);
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return new Promise(() => {});
}

async function threatModelCommand(args: string[]): Promise<number> {
  const target = args[0];
  if (!target) {
    console.error('Usage: security-vule threat-model <path> [--output FILE] [--with-dfd]');
    return 2;
  }
  let outputFile: string | undefined;
  let withDfd = false;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--output' || a === '-o') outputFile = args[++i];
    else if (a === '--with-dfd') withDfd = true;
  }
  const abs = require('path').resolve(target);
  if (!existsSync(abs)) {
    console.error(`Path not found: ${target}`);
    return 2;
  }
  const files = walkFiles(abs);
  console.error(`[security-vule] analyzing ${files.length} files in ${target} for threat model`);
  const allFindings: VulnerabilityFinding[] = [];
  for (const f of files) {
    let result: AnalysisResult;
    try {
      const src = readFileSync(f, 'utf-8');
      result = await analyzeFile(f, src);
    } catch (e) { continue; }
    for (const finding of result.vulnerabilities) allFindings.push(finding);
  }
  const { buildThreatModel } = await import('./threatmodel/stride.js');
  const tm = buildThreatModel(target, allFindings);
  if (withDfd) {
    const { generateDfd, dfdToMermaid } = await import('./threatmodel/dfd.js');
    const dfd = generateDfd(target, files);
    (tm as any).dfd = dfd;
    (tm as any).dfdMermaid = dfdToMermaid(dfd);
  }
  const json = JSON.stringify(tm, null, 2);
  if (outputFile) {
    writeFileSync(outputFile, json);
    console.error(`[security-vule] threat model written to ${outputFile}`);
  } else {
    console.log(json);
  }
  console.error(`[security-vule] ${tm.totalThreats} threats across STRIDE categories`);
  return 0;
}

function versionCommand(): number {
  console.log('security-vule 0.1.0');
  return 0;
}

export function verifyPocCommand(args: string[], deps?: { runner?: SpawnRunner; probe?: PortProbe }): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`verify-poc <findings.json>    Runtime PoC verification (calls poc-validator/verify_poc.py)
  <findings.json>          Output of 'security-vule scan --output' (must contain 'findings' key)
  --target=mock|dvwa|bwapp|sqlilabs|pikachu|auto|none
                           Target app (default: auto = detect reachable target)
  --output FILE | -o FILE  Verified results JSON (default: /tmp/sv_poc_verified.json)
  --python PY              Python binary (default: python3)
  --script PATH            verify_poc.py path (default: poc-validator/verify_poc.py)
  --timeout-ms N           Spawn timeout in ms (default: 180000)
  --help | -h              Show this help`);
    return Promise.resolve(0);
  }
  const findingsPath = args[0];
  if (!findingsPath) {
    console.error('Usage: security-vule verify-poc <findings.json> [--target=auto] [--output FILE]');
    return Promise.resolve(2);
  }
  if (!existsSync(findingsPath)) {
    console.error(`findings file not found: ${findingsPath}`);
    return Promise.resolve(2);
  }
  let target: PoCTarget = 'auto';
  let outputFile = '/tmp/sv_poc_verified.json';
  let pythonBin = 'python3';
  let scriptPath = 'poc-validator/verify_poc.py';
  let timeoutMs = 180_000;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--output' || a === '-o') outputFile = args[++i];
    else if (a === '--python') pythonBin = args[++i];
    else if (a === '--script') scriptPath = args[++i];
    else if (a === '--timeout-ms') timeoutMs = Number(args[++i]);
    else if (a.startsWith('--target=')) {
      const v = a.slice('--target='.length);
      if (!isPoCTarget(v)) { console.error(`invalid --target: ${v}`); return Promise.resolve(2); }
      target = v;
    }
  }
  const runVerify = async () => {
    const raw = readFileSync(findingsPath, 'utf-8');
    let parsed: any;
    try { parsed = JSON.parse(raw); } catch (e) {
      console.error(`failed to parse findings JSON: ${(e as Error).message}`);
      return 2;
    }
    const findings: VulnerabilityFinding[] = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.findings) ? parsed.findings : [];
    if (findings.length === 0) {
      console.error('no findings to verify (input must contain a "findings" array)');
      return 2;
    }
    const result = await runPoCVerification(findings, {
      target,
      pythonBin,
      scriptPath,
      timeoutMs,
      runner: deps?.runner,
      probe: deps?.probe,
    });
    if (!result.ok) {
      console.error(`[security-vule/verify-poc] ${result.message ?? 'verification skipped'}`);
      const fallback = { ok: false, skipped: result.skipped ?? 'unknown', message: result.message, findings };
      await Bun.write(outputFile, JSON.stringify(fallback, null, 2));
      return 1;
    }
    const output = {
      ok: true,
      verification: result.verification,
      merged: result.merged,
    };
    await Bun.write(outputFile, JSON.stringify(output, null, 2));
    const v = result.verification!;
    console.error(`[security-vule/verify-poc] ${v.verified} verified, ${v.unverified} not exploited, ${v.unconfirmed} unconfirmed`);
    console.error(`[security-vule/verify-poc] results written to ${outputFile}`);

    // 审计埋点：PoC 验证完成
    try {
      GLOBAL_AUDIT_LOGGER.log({
        action: 'poc.verified',
        result: 'ok',
        meta: {
          verified: v.verified,
          unverified: v.unverified,
          unconfirmed: v.unconfirmed,
        },
      });
    } catch (e) {
      console.warn(`[audit] poc.verified log failed: ${(e as Error).message}`);
    }

    return 0;
  };
  return runVerify();
}

export function generatePocCommand(args: string[], deps?: { router?: LLMRouter; now?: () => Date }): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`generate-poc <findings.json>  LLM-generated PoC candidates (no execution)
  <findings.json>          scan --output JSON
  --finding-id ID          Generate PoC for one specific finding (otherwise all)
  --output FILE | -o FILE  Output JSON (default: <input>.poc-gen.json)
  --model MODEL            LLM model id (e.g. gpt-4o-mini, glm-4)
  --provider NAME          Preferred provider (openai, anthropic, ollama, ...)
  --help | -h              Show this help`);
    return Promise.resolve(0);
  }
  const findingsPath = args[0];
  if (!findingsPath) {
    console.error('Usage: security-vule generate-poc <findings.json> [--finding-id ID] [--output FILE]');
    return Promise.resolve(2);
  }
  if (!existsSync(findingsPath)) {
    console.error(`findings file not found: ${findingsPath}`);
    return Promise.resolve(2);
  }
  let findingId: string | undefined;
  let outputFile: string | undefined;
  let model: string | undefined;
  let preferredProvider: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--finding-id') findingId = args[++i];
    else if (a === '--output' || a === '-o') outputFile = args[++i];
    else if (a === '--model') model = args[++i];
    else if (a === '--provider') preferredProvider = args[++i];
  }
  if (!outputFile) {
    outputFile = findingsPath.replace(/\.json$/i, '') + '.poc-gen.json';
  }
  const run = async () => {
    const raw = readFileSync(findingsPath, 'utf-8');
    let parsed: any;
    try { parsed = JSON.parse(raw); } catch (e) {
      console.error(`failed to parse findings JSON: ${(e as Error).message}`);
      return 2;
    }
    const findings: VulnerabilityFinding[] = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.findings) ? parsed.findings : [];
    const selected = findingId ? findings.filter(f => f.id === findingId) : findings;
    if (selected.length === 0) {
      console.error('no findings matched the selection');
      return 2;
    }
    let router: LLMRouter;
    try {
      router = deps?.router ?? createDefaultRouter();
    } catch (e) {
      console.error(`failed to create LLM router: ${(e as Error).message}`);
      return 2;
    }
    const candidates: any[] = [];
    const errors: any[] = [];
    for (const f of selected) {
      const r = await generatePocForFinding(f, {
        router,
        model,
        preferredProvider,
        now: deps?.now,
      });
      if (r.ok && r.candidate) candidates.push(r.candidate);
      else errors.push({ finding: f, error: r.error, raw: r.rawContent });
    }
    const out = {
      generatedAt: (deps?.now ?? (() => new Date()))().toISOString(),
      source: findingsPath,
      model: model ?? 'default',
      count: candidates.length,
      candidates,
      errors,
    };
    await Bun.write(outputFile, JSON.stringify(out, null, 2));
    console.error(`[security-vule/generate-poc] wrote ${candidates.length} candidates to ${outputFile}`);
    if (errors.length > 0) {
      console.error(`[security-vule/generate-poc] ${errors.length} errors (see file)`);
      return 1;
    }
    return 0;
  };
  return run();
}

export function usageCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`usage report           Generate AI usage aggregation report
  --since=30d|7d|24h|DATE  Start time (default: all)
  --until=now|DATE         End time (default: now)
  --by=capability|provider|model|day|project
                           Group by dimension (default: capability)
  --format=json|markdown   Output format (default: json)
  --usage-file PATH        Usage JSONL file path (default: .vule-usage.jsonl)
  --help | -h              Show this help`);
    return Promise.resolve(0);
  }

  const subCmd = args[0];
  if (subCmd !== 'report') {
    console.error('Usage: security-vule usage report [--since=30d] [--until=now] [--by=capability] [--format=json] [--usage-file PATH]');
    return Promise.resolve(2);
  }

  let sinceArg: string | undefined;
  let untilArg: string | undefined;
  let groupBy: GroupBy = 'capability';
  let format: ReportFormat = 'json';
  let usageFile: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--since=')) sinceArg = a.slice('--since='.length);
    else if (a === '--since') sinceArg = args[++i];
    else if (a.startsWith('--until=')) untilArg = a.slice('--until='.length);
    else if (a === '--until') untilArg = args[++i];
    else if (a.startsWith('--by=')) {
      const v = a.slice('--by='.length) as GroupBy;
      if (['capability', 'provider', 'model', 'day', 'project'].includes(v)) {
        groupBy = v;
      } else {
        console.error(`invalid --by value: ${v}`);
        return Promise.resolve(2);
      }
    } else if (a.startsWith('--format=')) {
      const v = a.slice('--format='.length) as ReportFormat;
      if (v === 'json' || v === 'markdown') {
        format = v;
      } else {
        console.error(`invalid --format value: ${v}`);
        return Promise.resolve(2);
      }
    } else if (a.startsWith('--usage-file=')) usageFile = a.slice('--usage-file='.length);
    else if (a === '--usage-file') usageFile = args[++i];
  }

  const since = parseTimeArg(sinceArg, 'start');
  const until = parseTimeArg(untilArg ?? 'now', 'end');

  const run = async () => {
    const store = new UsageStore(usageFile);
    const events = await store.readAll();
    const report = await generateReport(events, { since, until, groupBy, format });

    if (format === 'markdown') {
      console.log(formatMarkdown(report, groupBy));
    } else {
      console.log(JSON.stringify(report, null, 2));
    }
    return 0;
  };

  return run();
}

export function auditCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(auditHelp());
    return Promise.resolve(0);
  }

  const subCmd = args[0];
  if (!subCmd || (subCmd !== 'list' && subCmd !== 'export' && subCmd !== 'verify')) {
    console.error('Usage: security-vule audit <list|export|verify> [args]');
    return Promise.resolve(2);
  }

  let auditFile: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--audit-file=')) auditFile = a.slice('--audit-file='.length);
    else if (a === '--audit-file') auditFile = args[++i];
  }

  const logger = new AuditLogger({ filePath: auditFile });

  if (subCmd === 'list') {
    return auditListCommand(args.slice(1), logger);
  }

  if (subCmd === 'export') {
    return auditExportCommand(args.slice(1), logger);
  }

  if (subCmd === 'verify') {
    return auditVerifyCommand(logger);
  }

  return Promise.resolve(2);
}

async function auditListCommand(args: string[], logger: AuditLogger): Promise<number> {
  let actionFilter: string | undefined;
  let sinceArg: string | undefined;
  let untilArg: string | undefined;
  let limit = 100;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--action=')) actionFilter = a.slice('--action='.length);
    else if (a === '--action') actionFilter = args[++i];
    else if (a.startsWith('--since=')) sinceArg = a.slice('--since='.length);
    else if (a === '--since') sinceArg = args[++i];
    else if (a.startsWith('--until=')) untilArg = a.slice('--until='.length);
    else if (a === '--until') untilArg = args[++i];
    else if (a.startsWith('--limit=')) limit = parseInt(a.slice('--limit='.length), 10);
    else if (a === '--limit') limit = parseInt(args[++i], 10);
    else if (a.startsWith('--audit-file=') || a === '--audit-file') {
      if (a === '--audit-file') i++;
    }
  }

  const since = parseTimeArg(sinceArg, 'start');
  const until = parseTimeArg(untilArg ?? 'now', 'end');

  let events = await logger.readAll({ since, until, action: actionFilter });

  if (limit > 0 && events.length > limit) {
    events = events.slice(0, limit);
  }

  console.log(JSON.stringify(events, null, 2));
  return Promise.resolve(0);
}

async function auditExportCommand(args: string[], logger: AuditLogger): Promise<number> {
  let output: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--output=')) output = a.slice('--output='.length);
    else if (a === '--output' || a === '-o') output = args[++i];
    else if (a.startsWith('--audit-file=') || a === '--audit-file') {
      if (a === '--audit-file') i++;
    }
  }
  if (!output) {
    console.error('Usage: security-vule audit export --output FILE [--audit-file PATH]');
    return 2;
  }
  const events = await logger.readAll();
  const result = {
    exported_at: new Date().toISOString(),
    total: events.length,
    events,
  };
  await Bun.write(output, JSON.stringify(result, null, 2) + '\n');
  console.error(`[security-vule/audit] exported ${events.length} events to ${output}`);
  return 0;
}

async function auditVerifyCommand(logger: AuditLogger): Promise<number> {
  const result = await logger.verifyChain();
  console.log(JSON.stringify(result, null, 2));
  return result.valid ? 0 : 1;
}

export function auditHelp(): string {
  return `audit                          Audit log management
                       list           List audit events
                                      --action=NAME    Filter by action
                                      --since=7d|DATE  Start time
                                      --until=now|DATE End time
                                      --limit=N        Max events (default: 100)
                                      --audit-file PATH Audit file path
                       export         Export audit log
                                      --output FILE    Output file
                                      --audit-file PATH Audit file path
                       verify         Verify hash chain integrity
                                      --audit-file PATH Audit file path`;
}

function helpCommand(): number {
  console.log(`security-vule — Light Static + Heavy Verification

Usage: security-vule <command> [args]

Commands:
  scan <path>          Static analysis scan
                       --sarif         SARIF 2.1.0 output
                       --baseline FILE Skip findings already in baseline
                       --diff          Only show new findings since baseline
                       --output FILE   Write to file instead of stdout
                       --min-confidence N  Filter by confidence (0..1)
                       --status=LIST   Triage statuses to show (default: open,confirmed)
                       --state-file F  Use F instead of <target>/.vule-state.json
                       --sca=semgrep,trivy  Run external SCA tools (opt-in)
                       --with-poc      Run verify-poc after scan and merge results
                       --poc-target=mock|real|none
                       --poc-auto-confirm
  verify-poc <findings.json>  Runtime PoC verification via poc-validator/verify_poc.py
                       --target=mock|dvwa|bwapp|sqlilabs|pikachu|auto|none
                       --output FILE   Write verified results JSON
                       --python PY     Python binary (default: python3)
                       --script PATH   verify_poc.py path
                       --timeout-ms N  Spawn timeout (default: 180000)
  generate-poc <findings.json>  LLM-generated PoC candidates (no execution)
                       --finding-id ID Generate for one finding only
                       --output FILE   Output (default: <input>.poc-gen.json)
                       --model MODEL   LLM model id
                       --provider NAME Preferred provider
  threat-model <path>  Generate STRIDE threat model + DFD
                       --with-dfd      Include data flow diagram (mermaid)
                       --output FILE   Write to file
  state                Manage finding triage state
                       list            List all entries
                       set <fp> <st>   Set status for one fingerprint (--note "...")
                       clean           --fixed | --confirmed | --wontfix | --false-positive
                                      | --open [--older-than Nd]
                       export --output FILE
                       import --input FILE [--merge]
                       --state-file FILE  Override state file location
  usage report         Generate AI usage aggregation report
                       --since=30d|7d|24h|DATE  Start time
                       --until=now|DATE         End time
                       --by=capability|provider|model|day|project
                       --format=json|markdown   Output format
                       --usage-file PATH        Usage JSONL file path
  audit                Audit log management
                       list            List audit events
                       export          Export audit log
                       verify          Verify hash chain integrity
  version              Print version

Examples:
  security-vule scan ./src --sarif --output results.sarif
  security-vule scan ./src --baseline baseline.json --diff
  security-vule scan ./src --sca=semgrep,trivy
  security-vule scan ./src --with-poc --poc-target=mock
  security-vule scan ./src --with-poc --poc-target=mock --poc-auto-confirm
  security-vule verify-poc ./findings.json --target=mock --output ./verified.json
  security-vule generate-poc ./findings.json --output ./poc-candidates.json
  security-vule state list
  security-vule state set src/x.py:10:sqli confirmed --note "verified manually"
  security-vule state clean --fixed --older-than 30d
  security-vule threat-model ./src --with-dfd --output threat-model.json
`);
  return 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd === 'scan') return scanCommand(argv.slice(1));
  if (cmd === 'verify-poc') return verifyPocCommand(argv.slice(1));
  if (cmd === 'generate-poc') return generatePocCommand(argv.slice(1));
  if (cmd === 'threat-model') return threatModelCommand(argv.slice(1));
  if (cmd === 'state') return stateCommand(argv.slice(1));
  if (cmd === 'usage') return usageCommand(argv.slice(1));
  if (cmd === 'audit') return auditCommand(argv.slice(1));
  if (cmd === 'version') return versionCommand();
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return helpCommand();
  console.error(`Unknown command: ${cmd}`);
  return helpCommand();
}

if (import.meta.main) {
  main().then(c => process.exit(c)).catch(e => { console.error(e); process.exit(2); });
}

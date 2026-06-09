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

const SUPPORTED_EXT = new Set(['.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.go', '.rs', '.php', '.phtml']);

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

function loadBaseline(path: string | undefined): Set<string> {
  if (!path || !existsSync(path)) return new Set();
  const data = JSON.parse(readFileSync(path, 'utf-8'));
  const findings = Array.isArray(data) ? data : (data.findings || []);
  return new Set(findings.map((f: any) => `${f.file}:${f.line}:${f.type}`));
}

function toSarif(findings: VulnerabilityFinding[], targetPath: string, options: { stripSnippets?: boolean } = {}): unknown {
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
      partialFingerprints: [`${f.file}:${f.line}:${f.type}`],
    };
    if (!stripSnippets) {
      result.properties = { confidence: f.confidence, cwe: f.cwe };
    } else {
      result.properties = { confidence: f.confidence, cwe: f.cwe, codeStripped: true };
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

async function scanCommand(args: string[]): Promise<number> {
  const target = args[0];
  if (!target) {
    console.error('Usage: security-vule scan <path> [--sarif] [--baseline FILE] [--diff] [--output FILE]');
    return 2;
  }
  let outputFile: string | undefined;
  let sarifMode = false;
  let baselineFile: string | undefined;
  let diffMode = false;
  let minConfidence = 0;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--sarif') sarifMode = true;
    else if (a === '--baseline') baselineFile = args[++i];
    else if (a === '--diff') diffMode = true;
    else if (a === '--output' || a === '-o') outputFile = args[++i];
    else if (a === '--min-confidence') minConfidence = Number(args[++i]);
  }
  const abs = require('path').resolve(target);
  if (!existsSync(abs)) {
    console.error(`Path not found: ${target}`);
    return 2;
  }
  const files = walkFiles(abs);
  console.error(`[security-vule] scanning ${files.length} files in ${target}`);
  const allFindings: VulnerabilityFinding[] = [];
  for (const f of files) {
    let result: AnalysisResult;
    try {
      const src = readFileSync(f, 'utf-8');
      result = await analyzeFile(f, src);
    } catch (e) { console.error(`[skip] ${f}: ${(e as Error).message}`); continue; }
    for (const finding of result.vulnerabilities) {
      if (finding.confidence >= minConfidence) allFindings.push(finding);
    }
  }
  const baseline = loadBaseline(baselineFile);
  let visible = allFindings;
  if (diffMode) {
    visible = allFindings.filter(f => !baseline.has(`${f.file}:${f.line}:${f.type}`));
  }
  if (sarifMode) {
    const out = toSarif(visible, abs, { stripSnippets: true });
    const json = JSON.stringify(out, null, 2);
    if (outputFile) { writeFileSync(outputFile, json); console.error(`[security-vule] SARIF written to ${outputFile}`); }
    else process.stdout.write(json);
  } else {
    const summary = {
      target,
      files_scanned: files.length,
      total_findings: allFindings.length,
      new_findings: visible.length,
      findings: visible,
    };
    if (outputFile) { writeFileSync(outputFile, JSON.stringify(summary, null, 2)); console.error(`[security-vule] written to ${outputFile}`); }
    else console.log(JSON.stringify(summary, null, 2));
  }
  console.error(`[security-vule] ${allFindings.length} findings, ${visible.length} shown`);
  return visible.some(f => f.severity === 'CRITICAL') ? 1 : 0;
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
  threat-model <path>  Generate STRIDE threat model + DFD
                       --with-dfd      Include data flow diagram (mermaid)
                       --output FILE   Write to file
  version              Print version

Examples:
  security-vule scan ./src --sarif --output results.sarif
  security-vule scan ./src --baseline baseline.json --diff
  security-vule threat-model ./src --with-dfd --output threat-model.json
`);
  return 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd === 'scan') return scanCommand(argv.slice(1));
  if (cmd === 'threat-model') return threatModelCommand(argv.slice(1));
  if (cmd === 'version') return versionCommand();
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') return helpCommand();
  console.error(`Unknown command: ${cmd}`);
  return helpCommand();
}

main().then(c => process.exit(c)).catch(e => { console.error(e); process.exit(2); });

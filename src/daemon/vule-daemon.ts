/**
 * Persistent daemon — ralph-loop watcher for security-vule.
 *
 * Inspired by zclllyybb/OpenGiraffe (daemon-based multi-agent system).
 * Runs as a long-lived process that:
 * - watches a directory for code changes
 * - queues incremental scans
 * - persists findings to a baseline store
 * - emits events on a Unix socket (for IDE / CI consumers)
 * - supports graceful shutdown (SIGTERM / SIGINT)
 *
 * Usage:
 * const daemon = new VuleDaemon({ watchDir: '/path/to/project', socketPath: '/tmp/vule.sock' });
 * await daemon.start();
 *
 * Daemon lifecycle:
 * start() → watches files → enqueues scan → diff vs baseline → emits events
 * stop() → drains queue → closes socket → exits
 */

import { watch, FSWatcher } from 'fs';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { createServer, Server } from 'net';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface DaemonFinding {
  id: string;
  file: string;
  line: number;
  severity: FindingSeverity;
  type: string;
  message: string;
  timestamp: number;
  hash: string;
}

export interface DaemonEvent {
  type:
    | 'scan-started'
    | 'scan-completed'
    | 'scan-failed'
    | 'finding-added'
    | 'finding-removed'
    | 'baseline-updated';
  timestamp: number;
  payload: Record<string, unknown>;
}

export interface DaemonConfig {
  watchDir: string;
  socketPath: string;
  baselinePath?: string;
  scanIntervalMs?: number;
  debounceMs?: number;
  onEvent?: (event: DaemonEvent) => void | Promise<void>;
}

export interface DaemonState {
  running: boolean;
  startedAt: number;
  scansCompleted: number;
  findingsTotal: number;
  baselineSize: number;
  watchedFiles: number;
  uptime: number;
}

const DEFAULT_DEBOUNCE = 500;
const DEFAULT_INTERVAL = 30000;

export class VuleDaemon {
  private readonly config: DaemonConfig;
  private watcher: FSWatcher | null = null;
  private server: Server | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private startedAt = 0;
  private scansCompleted = 0;
  private baseline: Map<string, DaemonFinding> = new Map();
  private pendingFiles: Set<string> = new Set();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly queue: string[] = [];

  constructor(config: DaemonConfig) {
    this.config = {
      scanIntervalMs: DEFAULT_INTERVAL,
      debounceMs: DEFAULT_DEBOUNCE,
      ...config,
    };
    this.loadBaseline();
  }

  async start(): Promise<void> {
    if (this.running) throw new Error('Daemon already running');
    if (!existsSync(this.config.watchDir))
      throw new Error(`watchDir does not exist: ${this.config.watchDir}`);

    this.watcher = watch(this.config.watchDir, { recursive: true }, (_event, filename) => {
      if (filename && /\.(ts|tsx|js|jsx|py|php|java|c|cpp|h|hpp|go|rs)$/i.test(filename)) {
        this.queue.push(filename);
        this.scheduleDebouncedScan();
      }
    });

    this.timer = setInterval(
      () => this.runPeriodicScan(),
      this.config.scanIntervalMs ?? DEFAULT_INTERVAL
    );

    await this.startSocketServer();

    this.running = true;
    this.startedAt = Date.now();
    await this.emit({
      type: 'scan-started',
      timestamp: Date.now(),
      payload: { watchDir: this.config.watchDir },
    });
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;

    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    if (this.timer) clearInterval(this.timer);
    if (this.watcher) this.watcher.close();
    if (this.server) {
      await new Promise<void>((resolve) => this.server?.close(() => resolve()));
    }
    this.saveBaseline();
  }

  state(): DaemonState {
    return {
      running: this.running,
      startedAt: this.startedAt,
      scansCompleted: this.scansCompleted,
      findingsTotal: this.baseline.size,
      baselineSize: this.baseline.size,
      watchedFiles: this.queue.length,
      uptime: this.running ? Date.now() - this.startedAt : 0,
    };
  }

  scanNow(file?: string): Promise<DaemonFinding[]> {
    const targets = file ? [file] : Array.from(new Set(this.queue));
    return this.runScan(targets);
  }

  private scheduleDebouncedScan(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      const targets = Array.from(new Set(this.queue.splice(0)));
      void this.runScan(targets);
    }, this.config.debounceMs ?? DEFAULT_DEBOUNCE);
  }

  private async runPeriodicScan(): Promise<void> {
    const targets = Array.from(new Set(this.queue.splice(0)));
    if (targets.length === 0) return;
    await this.runScan(targets);
  }

  private async runScan(files: string[]): Promise<DaemonFinding[]> {
    if (files.length === 0) return [];
    const findings: DaemonFinding[] = [];

    for (const f of files) {
      try {
        const fullPath = join(this.config.watchDir, f);
        if (!existsSync(fullPath)) continue;
        const hash = await hashFile(fullPath);
        const fileFindings = await this.scanFile(fullPath, hash);
        findings.push(...fileFindings);
      } catch {
        // skip files we cannot read
      }
    }

    this.diffAgainstBaseline(findings);
    this.scansCompleted++;
    await this.emit({
      type: 'scan-completed',
      timestamp: Date.now(),
      payload: { filesScanned: files.length, findings: findings.length },
    });
    return findings;
  }

  private async scanFile(file: string, hash: string): Promise<DaemonFinding[]> {
    const code = readFileSync(file, 'utf8');
    const lines = code.split('\n');
    const findings: DaemonFinding[] = [];

    const patterns: Array<{ regex: RegExp; type: string; severity: FindingSeverity }> = [
      { regex: /\beval\s*\(\s*\$?_?GET/i, type: 'eval-injection', severity: 'critical' },
      { regex: /\bsystem\s*\(\s*\$?_?GET/i, type: 'command-injection', severity: 'critical' },
      { regex: /\bshell_exec\s*\(\s*\$?_?GET/i, type: 'command-injection', severity: 'critical' },
      { regex: /mysql_query\s*\([^)]*\$?_?GET/i, type: 'sql-injection', severity: 'critical' },
      { regex: /password\s*=\s*['"]\w{4,}/i, type: 'hardcoded-password', severity: 'high' },
    ];

    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.regex.test(lines[i] ?? '')) {
          findings.push({
            id: `${file}:${i + 1}:${p.type}`,
            file,
            line: i + 1,
            severity: p.severity,
            type: p.type,
            message: `${p.type} at line ${i + 1}`,
            timestamp: Date.now(),
            hash,
          });
        }
      }
    }
    return findings;
  }

  private diffAgainstBaseline(newFindings: DaemonFinding[]): void {
    const newMap = new Map<string, DaemonFinding>();
    for (const f of newFindings) newMap.set(f.id, f);

    const added: DaemonFinding[] = [];
    const removed: DaemonFinding[] = [];

    for (const [id, finding] of newMap) {
      if (!this.baseline.has(id)) {
        added.push(finding);
        void this.emit({
          type: 'finding-added',
          timestamp: Date.now(),
          payload: { id, file: finding.file, line: finding.line, severity: finding.severity },
        });
      }
    }

    for (const [id, finding] of this.baseline) {
      if (!newMap.has(id)) {
        removed.push(finding);
        void this.emit({
          type: 'finding-removed',
          timestamp: Date.now(),
          payload: { id, file: finding.file, line: finding.line },
        });
      }
    }

    this.baseline = newMap;
    this.saveBaseline();
    if (added.length > 0 || removed.length > 0) {
      void this.emit({
        type: 'baseline-updated',
        timestamp: Date.now(),
        payload: { added: added.length, removed: removed.length },
      });
    }
  }

  private async startSocketServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((socket) => {
        socket.on('data', (data) => {
          const cmd = data.toString().trim();
          if (cmd === 'STATE') {
            socket.write(JSON.stringify(this.state()) + '\n');
          } else if (cmd.startsWith('SCAN ')) {
            const file = cmd.slice(5).trim();
            void this.scanNow(file).then((f) => {
              socket.write(JSON.stringify({ count: f.length, findings: f.slice(0, 10) }) + '\n');
            });
          } else if (cmd === 'STOP') {
            void this.stop();
            socket.write(JSON.stringify({ status: 'stopped' }) + '\n');
            socket.end();
          } else {
            socket.write(JSON.stringify({ error: `unknown command: ${cmd}` }) + '\n');
          }
        });
      });
      this.server?.listen(this.config.socketPath, () => resolve());
      this.server?.on('error', reject);
    });
  }

  private async emit(event: DaemonEvent): Promise<void> {
    await this.config.onEvent?.(event);
  }

  private loadBaseline(): void {
    if (!this.config.baselinePath) return;
    if (!existsSync(this.config.baselinePath)) return;
    try {
      const data = JSON.parse(readFileSync(this.config.baselinePath, 'utf8')) as DaemonFinding[];
      this.baseline = new Map(data.map((f) => [f.id, f]));
    } catch {
      this.baseline = new Map();
    }
  }

  private saveBaseline(): void {
    if (!this.config.baselinePath) return;
    const dir = this.config.baselinePath.split('/').slice(0, -1).join('/');
    if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(
      this.config.baselinePath,
      JSON.stringify(Array.from(this.baseline.values()), null, 2)
    );
  }
}

async function hashFile(path: string): Promise<string> {
  const { createHash } = await import('crypto');
  const content = readFileSync(path, 'utf8');
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

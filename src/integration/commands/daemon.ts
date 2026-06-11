/**
 * vule daemon — persistent watcher command.
 *
 * Inspired by zclllyybb/OpenGiraffe (daemon-based multi-agent system).
 * Wraps VuleDaemon for CLI use with start/stop/status commands.
 */
import { VuleDaemon, type DaemonEvent } from '../../daemon/vule-daemon.js';
import { connect } from 'net';
import { existsSync } from 'fs';

export interface DaemonCliOptions {
  action: 'start' | 'stop' | 'status';
  watchDir: string;
  socketPath: string;
  baselinePath?: string;
  scanIntervalMs?: number;
  debounceMs?: number;
  json?: boolean;
}

export async function daemonCommand(options: DaemonCliOptions): Promise<void> {
  if (options.action === 'status') {
    await daemonStatus(options.socketPath, options.json ?? false);
    return;
  }

  if (options.action === 'stop') {
    await daemonStop(options.socketPath, options.json ?? false);
    return;
  }

  await daemonStart(options);
}

async function daemonStart(options: DaemonCliOptions): Promise<void> {
  const events: DaemonEvent[] = [];
  const daemon = new VuleDaemon({
    watchDir: options.watchDir,
    socketPath: options.socketPath,
    baselinePath: options.baselinePath ?? `${options.watchDir}/.vule/baseline.json`,
    scanIntervalMs: options.scanIntervalMs,
    debounceMs: options.debounceMs,
    onEvent: async (e) => {
      events.push(e);
      if (!options.json) printEvent(e);
    },
  });

  await daemon.start();

  if (options.json) {
    console.log(
      JSON.stringify(
        { status: 'started', state: daemon.state(), events: events.slice(0, 10) },
        null,
        2
      )
    );
  } else {
    console.log(`\n🌌 VuleDaemon started`);
    console.log(` watching: ${options.watchDir}`);
    console.log(` socket: ${options.socketPath}`);
    console.log(` baseline: ${options.baselinePath ?? `${options.watchDir}/.vule/baseline.json`}`);
    console.log(``);
    console.log(`Try in another terminal:`);
    console.log(` echo "STATE" | nc -U ${options.socketPath}`);
    console.log(` echo "SCAN path/to/file.php" | nc -U ${options.socketPath}`);
    console.log(``);
    console.log(`Press Ctrl-C to stop...`);
  }

  process.on('SIGINT', async () => {
    console.log(`\n🛑 Shutting down...`);
    await daemon.stop();
    if (options.json) {
      console.log(
        JSON.stringify(
          { status: 'stopped', state: daemon.state(), totalEvents: events.length },
          null,
          2
        )
      );
    }
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await daemon.stop();
    process.exit(0);
  });

  await new Promise(() => {});
}

async function daemonStop(socketPath: string, json: boolean): Promise<void> {
  try {
    const result = await sendSocketCommand(socketPath, 'STOP');
    if (json) {
      console.log(JSON.stringify({ action: 'stop', result }, null, 2));
    } else {
      console.log(JSON.parse(result).status === 'stopped' ? '✅ Daemon stopped' : `⚠️ ${result}`);
    }
  } catch (e) {
    if (json) {
      console.log(JSON.stringify({ action: 'stop', error: (e as Error).message }, null, 2));
    } else {
      console.error(`❌ Cannot reach daemon at ${socketPath}: ${(e as Error).message}`);
    }
  }
}

async function daemonStatus(socketPath: string, json: boolean): Promise<void> {
  try {
    const result = await sendSocketCommand(socketPath, 'STATE');
    if (json) {
      console.log(result);
    } else {
      const state = JSON.parse(result) as {
        running: boolean;
        uptime: number;
        findingsTotal: number;
        scansCompleted: number;
      };
      console.log(`\n🌌 VuleDaemon Status`);
      console.log(` running: ${state.running ? '✅ yes' : '❌ no'}`);
      console.log(` uptime: ${formatUptime(state.uptime)}`);
      console.log(` scans completed: ${state.scansCompleted}`);
      console.log(` baseline size: ${state.findingsTotal} findings`);
    }
  } catch (e) {
    if (json) {
      console.log(JSON.stringify({ action: 'status', error: (e as Error).message }, null, 2));
    } else {
      console.error(`❌ Daemon not running at ${socketPath}`);
    }
  }
}

function printEvent(e: DaemonEvent): void {
  const icons: Record<DaemonEvent['type'], string> = {
    'scan-started': '🔍',
    'scan-completed': '✅',
    'scan-failed': '❌',
    'finding-added': '➕',
    'finding-removed': '➖',
    'baseline-updated': '📊',
  };
  const icon = icons[e.type] ?? '•';
  console.log(`[${new Date(e.timestamp).toISOString()}] ${icon} ${e.type}`);
}

function formatUptime(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

function sendSocketCommand(socketPath: string, command: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!existsSync(socketPath)) {
      reject(new Error(`socket does not exist: ${socketPath}`));
      return;
    }
    const timer = setTimeout(() => reject(new Error('socket timeout')), 3000);
    let settled = false;
    const settle = (fn: () => void) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        fn();
      }
    };
    const client = connect(socketPath, () => {
      client.write(command + '\n');
    });
    const chunks: Buffer[] = [];
    client.on('data', (c: Buffer) => {
      chunks.push(c);
      settle(() => {
        client.end();
        resolve(Buffer.concat(chunks).toString().trim());
      });
    });
    client.on('end', () => {
      settle(() => resolve(Buffer.concat(chunks).toString().trim()));
    });
    client.on('error', (e) => {
      settle(() => reject(e));
    });
  });
}

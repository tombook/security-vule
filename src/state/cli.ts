import { join } from 'path';
import { StateManager } from './manager.js';
import {
  DEFAULT_STATE_FILENAME,
  STATE_STATUSES,
  isFindingStatus,
  type FindingStatus,
} from './types.js';
import { GLOBAL_AUDIT_LOGGER } from '../audit/logger.js';

export { DEFAULT_STATE_FILENAME };

export function resolveStatePath(target: string | undefined, override: string | undefined): string | null {
  if (override) return override;
  if (!target) return null;
  return join(target, DEFAULT_STATE_FILENAME);
}

const STATE_SUBCOMMANDS = ['list', 'set', 'clean', 'export', 'import'] as const;
type StateSubcommand = typeof STATE_SUBCOMMANDS[number];

export interface StateArgs {
  subcommand: StateSubcommand | null;
  fingerprint?: string;
  status?: FindingStatus;
  note?: string;
  stateFile?: string;
  output?: string;
  input?: string;
  merge: boolean;
  cleanStatus?: FindingStatus;
  cleanOlderThanMs?: number;
}

const STATE_DURATION_RE = /^(\d+)([smhdw])$/;

function parseDuration(value: string): number | undefined {
  const m = STATE_DURATION_RE.exec(value);
  if (!m) return undefined;
  const n = Number(m[1]);
  const unit = m[2];
  if (unit === 's') return n * 1000;
  if (unit === 'm') return n * 60 * 1000;
  if (unit === 'h') return n * 60 * 60 * 1000;
  if (unit === 'd') return n * 24 * 60 * 60 * 1000;
  if (unit === 'w') return n * 7 * 24 * 60 * 60 * 1000;
  return undefined;
}

function findFlag(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

export function parseStateArgs(args: string[]): StateArgs | { error: string } {
  const subcommand = args[0];
  if (!subcommand) return { error: 'missing subcommand' };
  if (!(STATE_SUBCOMMANDS as readonly string[]).includes(subcommand)) {
    return { error: `unknown subcommand: ${subcommand}` };
  }

  const out: StateArgs = { subcommand: subcommand as StateSubcommand, merge: false };
  out.stateFile = findFlag(args, '--state-file');

  if (subcommand === 'set') {
    const fp = args[1];
    const status = args[2];
    if (!fp || !status) return { error: 'set requires <fingerprint> <status>' };
    if (!isFindingStatus(status)) return { error: `invalid status: ${status}` };
    out.fingerprint = fp;
    out.status = status;
    out.note = findFlag(args, '--note');
  } else if (subcommand === 'clean') {
    if (hasFlag(args, '--fixed')) out.cleanStatus = 'fixed';
    if (hasFlag(args, '--confirmed')) out.cleanStatus = 'confirmed';
    if (hasFlag(args, '--wontfix')) out.cleanStatus = 'wontfix';
    if (hasFlag(args, '--false-positive')) out.cleanStatus = 'false_positive';
    if (hasFlag(args, '--open')) out.cleanStatus = 'open';
    const ot = findFlag(args, '--older-than');
    if (ot) {
      const ms = parseDuration(ot);
      if (ms == null) return { error: `invalid --older-than value: ${ot}` };
      out.cleanOlderThanMs = ms;
    }
    if (!out.cleanStatus && out.cleanOlderThanMs == null) {
      return { error: 'clean requires --fixed | --confirmed | --wontfix | --false-positive | --open OR --older-than' };
    }
  } else if (subcommand === 'export') {
    out.output = findFlag(args, '--output') ?? findFlag(args, '-o');
    if (!out.output) return { error: 'export requires --output FILE' };
  } else if (subcommand === 'import') {
    out.input = findFlag(args, '--input') ?? findFlag(args, '-i');
    if (!out.input) return { error: 'import requires --input FILE' };
    out.merge = hasFlag(args, '--merge');
  }

  return out;
}

export interface StateCommandOptions {
  target?: string;
  stateFile?: string;
}

export async function stateCommand(args: string[], options: StateCommandOptions = {}): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(stateHelp());
    return 0;
  }
  const parsed = parseStateArgs(args);
  if ('error' in parsed) {
    console.error(`Usage: security-vule state <${STATE_SUBCOMMANDS.join('|')}> [args]\n${parsed.error}`);
    return 2;
  }
  const override = parsed.stateFile ?? options.stateFile;
  const path = resolveStatePath(options.target, override);
  if (!path) {
    console.error('Usage: security-vule state <list|set|clean|export|import> --state-file FILE (or pass a target)');
    return 2;
  }
  const mgr = new StateManager(path);

  if (parsed.subcommand === 'list') {
    const all = await mgr.getAll();
    const keys = Object.keys(all).sort();
    if (keys.length === 0) {
      console.log('(no entries)');
      return 0;
    }
    console.log('FINGERPRINT                          STATUS          BY        AT                      NOTE');
    for (const fp of keys) {
      const e = all[fp];
      const note = e.note ?? '';
      console.log(
        `${fp.padEnd(38)}${e.status.padEnd(16)}${e.by.padEnd(10)}${e.at}${note ? '  ' + note : ''}`
      );
    }
    console.log(`\n${keys.length} entries`);
    return 0;
  }

  if (parsed.subcommand === 'set') {
    try {
      const oldStatus = await mgr.getStatus(parsed.fingerprint!);
      await mgr.setStatus(parsed.fingerprint!, parsed.status!, parsed.note);

      // 审计埋点：状态变更
      try {
        GLOBAL_AUDIT_LOGGER.log({
          action: 'finding.state_changed',
          target: parsed.fingerprint!,
          result: 'ok',
          meta: {
            old_status: oldStatus ?? 'open',
            new_status: parsed.status!,
            note: parsed.note ?? '',
          },
        });
      } catch (e) {
        console.warn(`[audit] finding.state_changed log failed: ${(e as Error).message}`);
      }

      console.log(`set ${parsed.fingerprint} → ${parsed.status}`);
      return 0;
    } catch (e) {
      console.error(`error: ${(e as Error).message}`);
      return 2;
    }
  }

  if (parsed.subcommand === 'clean') {
    const filter: { status?: FindingStatus; olderThanMs?: number } = {};
    if (parsed.cleanStatus) filter.status = parsed.cleanStatus;
    if (parsed.cleanOlderThanMs != null) filter.olderThanMs = parsed.cleanOlderThanMs;
    const removed = await mgr.clean(filter);
    console.log(`removed ${removed} entries`);
    return 0;
  }

  if (parsed.subcommand === 'export') {
    await mgr.exportTo(parsed.output!);
    console.log(`exported to ${parsed.output}`);
    return 0;
  }

  if (parsed.subcommand === 'import') {
    try {
      await mgr.importFrom(parsed.input!, { merge: parsed.merge });
      console.log(`imported from ${parsed.input}${parsed.merge ? ' (merged)' : ''}`);
      return 0;
    } catch (e) {
      console.error(`error: ${(e as Error).message}`);
      return 2;
    }
  }

  return 2;
}

export function stateHelp(): string {
  return `state                          Manage finding triage state
                       list           List all entries
                       set <fp> <st>  Set status for one fingerprint (--note "...")
                       clean          Clean entries (--fixed | --confirmed | --wontfix
                                      | --false-positive | --open) [--older-than Nd]
                       export --output FILE
                       import --input FILE [--merge]
                       --state-file FILE  Override state file location`;
}

export { STATE_STATUSES };
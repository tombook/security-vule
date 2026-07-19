import { watch, type FSWatcher } from 'fs';
import { join, extname, relative, sep } from 'path';

export interface WatchOptions {
  root: string;
  extensions: string[];
  debounceMs?: number;
  pollInterval?: number;
  ignoreDirs?: string[];
  onChange?: (changedFiles: string[]) => void | Promise<void>;
  onReady?: () => void;
}

export interface ScanWatcher {
  start(): Promise<void>;
  stop(): Promise<void>;
  isRunning(): boolean;
}

const DEFAULT_IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor'];
const DEFAULT_DEBOUNCE_MS = 300;

export function createWatcher(options: WatchOptions): ScanWatcher {
  const {
    root,
    extensions,
    debounceMs = DEFAULT_DEBOUNCE_MS,
    ignoreDirs = DEFAULT_IGNORE_DIRS,
    onChange,
    onReady,
  } = options;

  let watcher: FSWatcher | null = null;
  let running = false;
  let debounceTimer: Timer | null = null;
  const pendingFiles = new Set<string>();
  const extSet = new Set(extensions.map(e => e.toLowerCase()));
  const ignoreDirSet = new Set(ignoreDirs);

  function shouldIgnorePath(filePath: string): boolean {
    const relPath = relative(root, filePath);
    const parts = relPath.split(sep);
    for (const part of parts) {
      if (ignoreDirSet.has(part)) return true;
    }
    return false;
  }

  function hasValidExtension(filePath: string): boolean {
    const ext = extname(filePath).toLowerCase();
    return extSet.has(ext);
  }

  function flushDebounced() {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    if (pendingFiles.size === 0) return;
    const files = Array.from(pendingFiles);
    pendingFiles.clear();
    if (onChange && running) {
      Promise.resolve(onChange(files)).catch(err => {
        console.warn(`[watcher] onChange callback error: ${err.message}`);
      });
    }
  }

  function scheduleDebounce() {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(flushDebounced, debounceMs);
  }

  function handleFileChange(eventType: string, filename: string | null) {
    if (!running || !filename) return;

    const fullPath = join(root, filename);

    if (shouldIgnorePath(fullPath)) return;
    if (!hasValidExtension(fullPath)) return;

    pendingFiles.add(fullPath);
    scheduleDebounce();
  }

  async function start(): Promise<void> {
    if (running) return;

    try {
      watcher = watch(root, { recursive: true }, (eventType, filename) => {
        handleFileChange(eventType, filename);
      });

      watcher.on('error', (err) => {
        console.warn(`[watcher] watch error: ${err.message}`);
      });

      running = true;

      if (onReady) {
        Promise.resolve(onReady()).catch(err => {
          console.warn(`[watcher] onReady callback error: ${err.message}`);
        });
      }
    } catch (err) {
      console.warn(`[watcher] failed to start: ${(err as Error).message}`);
      throw err;
    }
  }

  async function stop(): Promise<void> {
    if (!running) return;

    running = false;

    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }

    pendingFiles.clear();

    if (watcher) {
      try {
        watcher.close();
      } catch (err) {
        console.warn(`[watcher] error closing watcher: ${(err as Error).message}`);
      }
      watcher = null;
    }
  }

  function isRunning(): boolean {
    return running;
  }

  return { start, stop, isRunning };
}

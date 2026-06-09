/**
 * vule visualize <report.html> — open existing HTML report in browser
 * Cross-platform: macOS (open), Linux (xdg-open), Windows (start)
 */
import { spawn } from 'child_process';

export async function visualizeCommand(path: string): Promise<void> {
  const url = `file://${process.cwd()}/${path}`;
  const platform = process.platform;
  let cmd: string, args: string[];
  if (platform === 'darwin') { cmd = 'open'; args = [url]; }
  else if (platform === 'win32') { cmd = 'start'; args = [url]; }
  else { cmd = 'xdg-open'; args = [url]; }
  console.log(`Opening ${url} via ${cmd}...`);
  spawn(cmd, args, { stdio: 'inherit' });
}
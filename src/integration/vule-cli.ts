/**
 * VuleEngine CLI — main entry point.
 * Usage: vule <command> [options]
 */
import { Command } from 'commander';
import { analyzeCommand } from './commands/analyze.js';
import { dimensionCommand } from './commands/dimension.js';
import { visualizeCommand } from './commands/visualize.js';
import { serverCommand } from './commands/server.js';
import { DIMENSIONS } from '../engine/dimensions/registry.js';

const program = new Command();

program
  .name('vule')
  .description('🌌 VuleEngine — cosmic-galaxy aligned security analysis')
  .version('0.3.0');

program
  .command('analyze <path>')
  .description('Analyze a source file or directory')
  .option('-c, --config <path>', 'Path to vule.yaml config')
  .option('-f, --format <fmt>', 'Output format: json | html | markdown', 'json')
  .option('-e, --export <path>', 'Export report to file')
  .option('-d, --dimensions <list>', 'Comma-separated list of dimensions')
  .action((path: string, opts: any) => analyzeCommand(path, opts));

program
  .command('dimension <name> <file>')
  .description('Run a single dimension detector on a file')
  .action((name: string, file: string) => dimensionCommand(name, file));

program
  .command('visualize <report.html>')
  .description('Open an HTML report in the default browser')
  .action((path: string) => visualizeCommand(path));

program
  .command('server')
  .description('Start web UI server')
  .option('-p, --port <port>', 'Port number', '3000')
  .action((opts: any) => serverCommand({ port: parseInt(opts.port, 10) }));

program
  .command('list-dimensions')
  .description('List all available cosmic-galaxy dimensions')
  .action(() => {
    console.log('\n🌌 Cosmic-Galaxy Dimensions:\n');
    for (const [name, dim] of Object.entries(DIMENSIONS)) {
      console.log(`  ${name.padEnd(15)} weight=${dim.weight.toFixed(2)}`);
    }
  });

program.parse(process.argv);
/**
 * VuleEngine CLI — main entry point.
 * Usage: vule <command> [options]
 */
import { Command, type OptionValues } from 'commander';
import { analyzeCommand, type AnalyzeOptions } from './commands/analyze.js';
import { dimensionCommand } from './commands/dimension.js';
import { visualizeCommand } from './commands/visualize.js';
import { serverCommand, type ServerOptions } from './commands/server.js';
import { workflowCommand, type WorkflowCliOptions } from './commands/workflow.js';
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
  .action((path: string, opts: OptionValues) => analyzeCommand(path, opts as AnalyzeOptions));

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
  .action((opts: OptionValues) =>
    serverCommand({ port: parseInt(opts.port as string, 10) } as ServerOptions)
  );

program
  .command('list-dimensions')
  .description('List all available cosmic-galaxy dimensions')
  .action(() => {
    console.log('\n🌌 Cosmic-Galaxy Dimensions:\n');
    for (const [name, dim] of Object.entries(DIMENSIONS)) {
      console.log(` ${name.padEnd(15)} weight=${dim.weight.toFixed(2)}`);
    }
  });

program
  .command('workflow <target>')
  .description('Run6-stage multi-agent security review pipeline (spec→plan→build→test→review→ship)')
  .option('--llm', 'Enable LLM-enhanced detection')
  .option('--owasp', 'Enable OWASP Agentic Top10 (2026) scan')
  .option('--poc', 'Enable PoC verification')
  .option('--stage <name>', 'Run only one stage: SPEC|PLAN|BUILD|TEST|REVIEW|SHIP')
  .option('--skip <stage>', 'Skip one stage')
  .option('--resume <stage>', 'Resume workflow from given stage')
  .option('--json', 'Output machine-readable JSON')
  .action((target: string, opts: OptionValues) => {
    const o: WorkflowCliOptions = {
      llm: !!opts.llm,
      owasp: !!opts.owasp,
      poc: !!opts.poc,
      json: !!opts.json,
      stage: opts.stage as WorkflowCliOptions['stage'],
      skip: opts.skip as WorkflowCliOptions['skip'],
      resume: opts.resume as WorkflowCliOptions['resume'],
    };
    return workflowCommand(target, o);
  });

program.parse(process.argv);

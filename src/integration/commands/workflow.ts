/**
 * vule workflow <target> — run6-stage security review pipeline.
 * Inspired by Snowflake-Labs/cocoplus workflow pattern.
 */
import { Workflow, type StageName } from '../../engine/workflow.js';
import { detectLanguage } from '../../engine/parser.js';

export interface WorkflowCliOptions {
  llm?: boolean;
  owasp?: boolean;
  poc?: boolean;
  stage?: StageName;
  skip?: StageName;
  resume?: StageName;
  json?: boolean;
}

export async function workflowCommand(target: string, options: WorkflowCliOptions): Promise<void> {
  const language = detectLanguage(target);
  const wf = new Workflow({
    target,
    language,
    enableLlm: !!options.llm,
    enableOwaspAgentic: !!options.owasp,
    enablePoC: !!options.poc,
  });

  if (options.skip) wf.skipStage(options.skip);
  if (options.resume) wf.resume(options.resume);

  if (options.stage) {
    const artifact = await wf.runStage(options.stage);
    if (options.json) {
      console.log(JSON.stringify({ stage: artifact, summary: wf.summary() }, null, 2));
    } else {
      printStage(artifact);
    }
    return;
  }

  const summary = await wf.runAll();
  if (options.json) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    printSummary(summary);
  }
}

function printStage(artifact: {
  stage: string;
  status: string;
  durationMs: number;
  output: Record<string, unknown>;
  error?: string;
}): void {
  const icon = artifact.status === 'completed' ? '✅' : artifact.status === 'failed' ? '❌' : '⏭️';
  console.log(`${icon} ${artifact.stage} — ${artifact.status} (${artifact.durationMs}ms)`);
  if (artifact.error) console.log(` error: ${artifact.error}`);
  for (const [k, v] of Object.entries(artifact.output)) {
    const display = typeof v === 'object' ? JSON.stringify(v) : String(v);
    const truncated = display.length > 120 ? display.slice(0, 120) + '...' : display;
    console.log(` ${k}: ${truncated}`);
  }
}

function printSummary(summary: {
  progress: { completed: number; total: number; percent: number };
  result: string;
  totalDurationMs: number;
  stages: Record<string, { stage: string; status: string; durationMs: number }>;
  config: {
    target: string;
    language: string;
    enableLlm?: boolean;
    enableOwaspAgentic?: boolean;
    enablePoC?: boolean;
  };
}): void {
  console.log(`\n🌌6-Stage Workflow Summary`);
  console.log(` target: ${summary.config.target} (${summary.config.language})`);
  console.log(
    ` progress: ${summary.progress.completed}/${summary.progress.total} (${summary.progress.percent}%)`
  );
  console.log(` result: ${summary.result.toUpperCase()}`);
  console.log(` total: ${summary.totalDurationMs}ms`);
  console.log(``);
  for (const [name, s] of Object.entries(summary.stages)) {
    const icon =
      s.status === 'completed'
        ? '✅'
        : s.status === 'failed'
          ? '❌'
          : s.status === 'skipped'
            ? '⏭️'
            : '⏸️';
    console.log(` ${icon} ${name.padEnd(8)} ${s.status.padEnd(10)} ${s.durationMs}ms`);
  }
  if (summary.config.enableLlm || summary.config.enableOwaspAgentic || summary.config.enablePoC) {
    console.log(``);
    console.log(` options:`);
    if (summary.config.enableLlm) console.log(` • LLM enhanced`);
    if (summary.config.enableOwaspAgentic) console.log(` • OWASP Agentic Top10`);
    if (summary.config.enablePoC) console.log(` • PoC verification`);
  }
}

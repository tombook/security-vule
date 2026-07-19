/**
 * 用量聚合报告生成器
 * 支持按 capability / provider / model / day / project 分组
 */
import type { UsageEvent } from './types.js';

export type GroupBy = 'capability' | 'provider' | 'model' | 'day' | 'project';
export type ReportFormat = 'json' | 'markdown';

export interface ReportOptions {
  since?: Date;
  until?: Date;
  groupBy: GroupBy;
  format?: ReportFormat;
  project?: string;
}

export interface ReportGroup {
  key: string;
  events: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
}

export interface UsageReport {
  period: { since: string; until: string };
  total_events: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_tokens: number;
  total_cost_usd: number;
  groups: ReportGroup[];
}

/**
 * 数字格式化（添加千分位）
 */
function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * 金额格式化
 */
function formatCost(usd: number): string {
  return `$${usd.toFixed(4)}`;
}

/**
 * 获取分组键
 */
function getGroupKey(event: UsageEvent, groupBy: GroupBy): string {
  switch (groupBy) {
    case 'day':
      return event.ts.slice(0, 10);
    case 'capability':
      return event.capability;
    case 'provider':
      return event.provider ?? 'unknown';
    case 'model':
      return event.model ?? 'unknown';
    case 'project':
      if (event.scan_id) {
        return event.scan_id.slice(0, 8);
      }
      if (event.project) {
        return event.project;
      }
      return 'unknown';
    default:
      return 'unknown';
  }
}

/**
 * 过滤事件（按时间范围）
 */
function filterEvents(events: UsageEvent[], since?: Date, until?: Date): UsageEvent[] {
  return events.filter(event => {
    const eventTime = new Date(event.ts).getTime();
    if (since && eventTime < since.getTime()) return false;
    if (until && eventTime > until.getTime()) return false;
    return true;
  });
}

/**
 * 生成聚合报告
 */
export async function generateReport(
  events: UsageEvent[],
  options: ReportOptions
): Promise<UsageReport> {
  const filtered = filterEvents(events, options.since, options.until);

  const groupMap = new Map<string, ReportGroup>();

  for (const event of filtered) {
    const key = getGroupKey(event, options.groupBy);
    const pt = event.prompt_tokens ?? 0;
    const ct = event.completion_tokens ?? 0;
    const cost = event.cost_usd ?? 0;
    const existing = groupMap.get(key);
    if (existing) {
      existing.events += 1;
      existing.prompt_tokens += pt;
      existing.completion_tokens += ct;
      existing.total_tokens += pt + ct;
      existing.cost_usd += cost;
    } else {
      groupMap.set(key, {
        key,
        events: 1,
        prompt_tokens: pt,
        completion_tokens: ct,
        total_tokens: pt + ct,
        cost_usd: cost,
      });
    }
  }

  const groups = Array.from(groupMap.values()).sort((a, b) => b.cost_usd - a.cost_usd);

  let total_events = 0;
  let total_prompt_tokens = 0;
  let total_completion_tokens = 0;
  let total_cost_usd = 0;

  for (const g of groups) {
    total_events += g.events;
    total_prompt_tokens += g.prompt_tokens;
    total_completion_tokens += g.completion_tokens;
    total_cost_usd += g.cost_usd;
  }

  const total_tokens = total_prompt_tokens + total_completion_tokens;

  const sinceStr = options.since ? options.since.toISOString().slice(0, 10) : 'all';
  const untilStr = options.until ? options.until.toISOString().slice(0, 10) : 'now';

  return {
    period: { since: sinceStr, until: untilStr },
    total_events,
    total_prompt_tokens,
    total_completion_tokens,
    total_tokens,
    total_cost_usd,
    groups,
  };
}

/**
 * 格式化为 Markdown
 */
export function formatMarkdown(report: UsageReport, groupBy: GroupBy = 'capability'): string {
  const lines: string[] = [];

  lines.push('# AI 用量报告');
  lines.push('');
  lines.push(`**周期**: ${report.period.since} ~ ${report.period.until}`);
  lines.push(`**总调用**: ${formatNumber(report.total_events)} 次`);
  lines.push(
    `**总 token**: ${formatNumber(report.total_tokens)} ` +
    `(prompt: ${formatNumber(report.total_prompt_tokens)} / ` +
    `completion: ${formatNumber(report.total_completion_tokens)})`
  );
  lines.push(`**总成本**: ${formatCost(report.total_cost_usd)}`);
  lines.push('');

  const groupByLabel: Record<GroupBy, string> = {
    capability: '功能',
    provider: '提供商',
    model: '模型',
    day: '日期',
    project: '项目',
  };

  lines.push(`## 按 ${groupByLabel[groupBy]} 分组`);
  lines.push('');
  lines.push('| 分组 | 调用次数 | Prompt tokens | Completion tokens | 总成本 |');
  lines.push('|---|---:|---:|---:|---:|');

  for (const g of report.groups) {
    lines.push(
      `| ${g.key} | ${formatNumber(g.events)} | ${formatNumber(g.prompt_tokens)} | ` +
      `${formatNumber(g.completion_tokens)} | ${formatCost(g.cost_usd)} |`
    );
  }

  return lines.join('\n');
}

/**
 * 解析时间参数（支持 30d / 7d / 24h / 2026-06-01 / now）
 */
export function parseTimeArg(arg: string | undefined, base: 'start' | 'end' = 'end'): Date | undefined {
  if (!arg) return undefined;
  if (arg === 'now') return new Date();

  const relativeMatch = arg.match(/^(\d+)(d|h|m)$/);
  if (relativeMatch) {
    const value = parseInt(relativeMatch[1], 10);
    const unit = relativeMatch[2];
    const now = Date.now();
    let ms = 0;
    switch (unit) {
      case 'd': ms = value * 24 * 60 * 60 * 1000; break;
      case 'h': ms = value * 60 * 60 * 1000; break;
      case 'm': ms = value * 60 * 1000; break;
    }
    return new Date(now - ms);
  }

  const dateMatch = arg.match(/^(\d{4}-\d{2}-\d{2})$/);
  if (dateMatch) {
    const d = new Date(arg);
    if (base === 'end') {
      d.setHours(23, 59, 59, 999);
    } else {
      d.setHours(0, 0, 0, 0);
    }
    return d;
  }

  const d = new Date(arg);
  if (!isNaN(d.getTime())) return d;

  return undefined;
}

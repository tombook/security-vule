// 用量事件类型定义

export interface UsageEvent {
  ts: string;
  capability: string;
  provider?: string;
  model?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  cost_usd?: number;
  file_hash?: string;
  scan_id?: string;
  meta?: Record<string, unknown>;
}

export const USAGE_FILENAME = '.vule-usage.jsonl';

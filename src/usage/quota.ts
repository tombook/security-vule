/**
 * 配额管理器
 *
 * 监控 LLM 用量，在接近或超过配额时发出警告。
 * 支持 tokens、成本、调用次数三种配额维度，
 * 基于滑动时间窗口计算，不阻塞正常流程。
 */

import type { UsageEvent } from './types.js';
import type { UsageStore } from './store.js';

export interface QuotaConfig {
  /** 周期内最大总 tokens */
  maxTokens?: number;
  /** 周期内最大成本（USD） */
  maxCostUsd?: number;
  /** 周期内最大调用次数 */
  maxCalls?: number;
  /** 时间窗口，默认 24h */
  windowMs?: number;
  /** 用量文件路径，默认 .vule-usage.jsonl */
  usageFile?: string;
  /** 警告回调，默认 console.warn */
  onWarn?: (info: QuotaWarning) => void;
}

export interface QuotaWarning {
  type: 'tokens' | 'cost' | 'calls';
  current: number;
  limit: number;
  percentage: number;
  windowMs: number;
}

/** 警告触发阈值（百分比） */
const WARN_THRESHOLD = 80;

export class QuotaManager {
  private config: Required<Pick<QuotaConfig, 'windowMs'>> & Omit<QuotaConfig, 'windowMs'>;

  constructor(config: QuotaConfig = {}) {
    this.config = {
      windowMs: config.windowMs ?? 24 * 60 * 60 * 1000,
      ...config,
    };
  }

  /**
   * 检查当前用量是否接近/超过配额，返回警告列表
   * 只计算最近 windowMs 窗口内的事件
   */
  check(events: UsageEvent[]): QuotaWarning[] {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    // 只统计窗口内的事件
    const windowEvents = events.filter(e => {
      const ts = Date.parse(e.ts);
      return !Number.isNaN(ts) && ts >= windowStart;
    });

    const warnings: QuotaWarning[] = [];

    // 统计总 tokens
    if (this.config.maxTokens !== undefined && this.config.maxTokens > 0) {
      const totalTokens = windowEvents.reduce((sum, e) => {
        const prompt = e.prompt_tokens ?? 0;
        const completion = e.completion_tokens ?? 0;
        return sum + prompt + completion;
      }, 0);
      const percentage = (totalTokens / this.config.maxTokens) * 100;
      if (percentage >= WARN_THRESHOLD) {
        warnings.push({
          type: 'tokens',
          current: totalTokens,
          limit: this.config.maxTokens,
          percentage,
          windowMs: this.config.windowMs,
        });
      }
    }

    // 统计总成本
    if (this.config.maxCostUsd !== undefined && this.config.maxCostUsd > 0) {
      const totalCost = windowEvents.reduce((sum, e) => sum + (e.cost_usd ?? 0), 0);
      const percentage = (totalCost / this.config.maxCostUsd) * 100;
      if (percentage >= WARN_THRESHOLD) {
        warnings.push({
          type: 'cost',
          current: totalCost,
          limit: this.config.maxCostUsd,
          percentage,
          windowMs: this.config.windowMs,
        });
      }
    }

    // 统计调用次数
    if (this.config.maxCalls !== undefined && this.config.maxCalls > 0) {
      const totalCalls = windowEvents.length;
      const percentage = (totalCalls / this.config.maxCalls) * 100;
      if (percentage >= WARN_THRESHOLD) {
        warnings.push({
          type: 'calls',
          current: totalCalls,
          limit: this.config.maxCalls,
          percentage,
          windowMs: this.config.windowMs,
        });
      }
    }

    // 触发警告回调
    if (this.config.onWarn) {
      for (const warning of warnings) {
        try {
          this.config.onWarn(warning);
        } catch {
          // 回调异常不影响主流程
        }
      }
    }

    return warnings;
  }

  /**
   * 便捷方法：从 store 读取最近 windowMs 的事件并检查
   */
  async checkFromStore(store: UsageStore): Promise<QuotaWarning[]> {
    const since = new Date(Date.now() - this.config.windowMs);
    const events = await store.readAll({ since });
    return this.check(events);
  }

  /**
   * 是否已超限（任何一项超 100%）
   */
  isExceeded(warnings: QuotaWarning[]): boolean {
    return warnings.some(w => w.percentage >= 100);
  }
}

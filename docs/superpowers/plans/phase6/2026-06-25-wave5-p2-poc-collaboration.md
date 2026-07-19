# 第五波 P2 计划:PoC 沙箱与协作

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 PoC 沙箱能力(DFG 驱动生成、N-best 候选、AI 对话审核)和 Finding 协作能力(8 态状态机、GitLab/Jira 集成、PDF 报告)。

**Architecture:** 在现有 poc/ 上扩展生成质量;在 finding/ 上扩展状态机;在 integrations/ 添加 GitLab + Jira;在 report/ 添加 PDF。

**Tech Stack:** TypeScript, Express, PDFKit, fetch (GitLab API), Jira REST API v3

---

## 文件结构

```
src/
├── poc/
│   ├── poc-ai-generator.ts         # 重构: DFG 感知 + N-best
│   ├── poc-chat.ts                 # 新增: AI 对话辅助审核
│   └── poc-ranker.ts               # 新增: 多候选打分
├── finding/
│   ├── finding-state.ts            # 新增: 8 态状态机
│   └── state-validator.ts          # 新增: 合法转移校验
├── integrations/
│   ├── gitlab-issues.ts            # 新增: GitLab Issue 集成
│   └── jira.ts                     # 新增: Jira 集成
├── report/
│   ├── report-pdf.ts               # 新增: 单 Finding PDF 报告
│   └── weekly-report.ts            # 新增: 周报聚合
tests/
├── unit/
│   ├── poc/ai-generator-dfg.test.ts
│   ├── poc/poc-chat.test.ts
│   ├── finding/finding-state.test.ts
│   ├── integrations/gitlab-issues.test.ts
│   ├── integrations/jira.test.ts
│   └── report/report-pdf.test.ts
```

---

## 任务 1: Finding 8 态状态机

**Files:**
- Create: `src/finding/finding-state.ts`
- Modify: `src/auth/finding-types.ts`
- Test: `tests/unit/finding/finding-state.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/finding/finding-state.test.ts
import { describe, it, expect } from 'vitest';
import { FindingState, canTransition, transition, VALID_TRANSITIONS } from '../../../src/finding/finding-state';

describe('FindingState', () => {
  it('should have 8 states', () => {
    expect(Object.values(FindingState).length).toBe(8);
    expect(FindingState.REGRESSED).toBe('regressed');
    expect(FindingState.ESCALATED).toBe('escalated');
  });

  it('should allow open → in_progress', () => {
    expect(canTransition(FindingState.OPEN, FindingState.IN_PROGRESS)).toBe(true);
  });

  it('should allow in_progress → fixed', () => {
    expect(canTransition(FindingState.IN_PROGRESS, FindingState.FIXED)).toBe(true);
  });

  it('should allow fixed → regressed (re-detected on rescan)', () => {
    expect(canTransition(FindingState.FIXED, FindingState.REGRESSED)).toBe(true);
  });

  it('should allow regressed → in_progress (auto-reopen)', () => {
    expect(canTransition(FindingState.REGRESSED, FindingState.IN_PROGRESS)).toBe(true);
  });

  it('should allow open → escalated (push to customer)', () => {
    expect(canTransition(FindingState.OPEN, FindingState.ESCALATED)).toBe(true);
  });

  it('should allow any → false_positive / accepted_risk (close)', () => {
    expect(canTransition(FindingState.OPEN, FindingState.FALSE_POSITIVE)).toBe(true);
    expect(canTransition(FindingState.OPEN, FindingState.ACCEPTED_RISK)).toBe(true);
    expect(canTransition(FindingState.IN_PROGRESS, FindingState.FALSE_POSITIVE)).toBe(true);
  });

  it('should not allow fixed → open', () => {
    expect(canTransition(FindingState.FIXED, FindingState.OPEN)).toBe(false);
  });

  it('should throw on invalid transition', () => {
    expect(() => transition(FindingState.OPEN, FindingState.REGRESSED)).toThrow();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/finding/finding-state.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 finding-state.ts**

```typescript
// src/finding/finding-state.ts
/**
 * Finding 状态机 — 对齐设计文档 §6.1
 *
 * 8 态:
 *   open                  新发现待处理
 *   in_progress           修复中
 *   fixed                 已修复
 *   regressed             回退 (修复后再次出现)
 *   escalated             升级给客户
 *   confirmed             PoC 验证成功
 *   false_positive        误报, 关闭
 *   accepted_risk         接受风险, 关闭
 */

export enum FindingState {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  FIXED = 'fixed',
  REGRESSED = 'regressed',
  ESCALATED = 'escalated',
  CONFIRMED = 'confirmed',
  FALSE_POSITIVE = 'false_positive',
  ACCEPTED_RISK = 'accepted_risk',
}

export const VALID_TRANSITIONS: Record<FindingState, FindingState[]> = {
  [FindingState.OPEN]: [
    FindingState.IN_PROGRESS,
    FindingState.ESCALATED,
    FindingState.CONFIRMED,
    FindingState.FALSE_POSITIVE,
    FindingState.ACCEPTED_RISK,
  ],
  [FindingState.IN_PROGRESS]: [
    FindingState.FIXED,
    FindingState.OPEN,         // 取消修复
    FindingState.FALSE_POSITIVE,
    FindingState.ACCEPTED_RISK,
  ],
  [FindingState.FIXED]: [
    FindingState.REGRESSED,    // 复测发现
  ],
  [FindingState.REGRESSED]: [
    FindingState.IN_PROGRESS,  // 自动重开
    FindingState.OPEN,
  ],
  [FindingState.ESCALATED]: [
    FindingState.IN_PROGRESS,  // 客户开始修
    FindingState.FIXED,        // 客户报告修复
    FindingState.FALSE_POSITIVE,
    FindingState.ACCEPTED_RISK,
  ],
  [FindingState.CONFIRMED]: [
    FindingState.IN_PROGRESS,
    FindingState.FIXED,
    FindingState.FALSE_POSITIVE,
    FindingState.ACCEPTED_RISK,
  ],
  [FindingState.FALSE_POSITIVE]: [],
  [FindingState.ACCEPTED_RISK]: [],
};

export function canTransition(from: FindingState, to: FindingState): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

export function transition(from: FindingState, to: FindingState): FindingState {
  if (!canTransition(from, to)) {
    throw new Error(`Invalid finding state transition: ${from} -> ${to}`);
  }
  return to;
}

export function isClosed(state: FindingState): boolean {
  return state === FindingState.FALSE_POSITIVE || state === FindingState.ACCEPTED_RISK;
}
```

- [ ] **Step 4: 修改 finding-types.ts 使用枚举**

修改 [src/auth/finding-types.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/finding-types.ts):

```typescript
import { FindingState } from '../finding/finding-state.js';

export type { FindingState };

// Finding.status 类型改为 FindingState
export interface Finding {
  // ...
  status: FindingState;
  // ...
}
```

并修改 finding-manager.ts 的 `updateStatus` 增加合法转移校验:

```typescript
import { canTransition as canTransitionFinding } from '../finding/finding-state.js';

async updateStatus(findingId: string, newStatus: FindingState): Promise<Finding> {
  const f = findings.get(findingId);
  if (!f) throw new Error('Finding not found');
  if (!canTransitionFinding(f.status, newStatus)) {
    throw new Error(`Invalid transition: ${f.status} -> ${newStatus}`);
  }
  f.status = newStatus;
  return f;
}
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/finding/finding-state.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/finding/finding-state.ts src/auth/finding-types.ts src/auth/finding-manager.ts tests/unit/finding/finding-state.test.ts
git commit -m "feat(finding): 8-state machine with regressed/escalated per design §6.1"
```

---

## 任务 2: PoC AI 生成 DFG 感知

**Files:**
- Modify: `src/poc/ai-poc-generator.ts`
- Test: `tests/unit/poc/ai-generator-dfg.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/poc/ai-generator-dfg.test.ts
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../src/llm/router', () => ({
  llmRouter: {
    generateCompletion: vi.fn().mockResolvedValue({
      text: 'def exploit():\n    pass',
      usage: { promptTokens: 200, completionTokens: 100 },
      model: 'gpt-4',
    }),
  },
}));

import { aiPoCGenerator } from '../../../src/poc/ai-poc-generator';

describe('AIPoCGenerator with DFG data flow', () => {
  it('should include DFG path in prompt context', async () => {
    await aiPoCGenerator.generate({
      finding: {
        ruleId: 'sqli-001',
        title: 'SQL Injection in query.ts',
        cwe: 'CWE-89',
        severity: 'high',
        codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
      },
      dataFlowPath: {
        source: 'req.query.id',
        sinks: ['db.query'],
        path: ['controller.ts:25', 'query.ts:12'],
        sanitizers: [],
      },
      language: 'javascript',
    } as any);

    // 验证 LLM 调用时 prompt 包含 DFG 信息
    const { llmRouter } = await import('../../../src/llm/router');
    const call = vi.mocked(llmRouter.generateCompletion).mock.calls[0][0];
    expect(call.prompt).toContain('req.query.id');
    expect(call.prompt).toContain('db.query');
    expect(call.prompt).toContain('controller.ts:25');
  });

  it('should generate N-best candidates (top 3)', async () => {
    const { llmRouter } = await import('../../../src/llm/router');
    (vi.mocked(llmRouter.generateCompletion) as any)
      .mockResolvedValueOnce({ text: 'def exploit_v1(): pass', usage: { promptTokens: 100, completionTokens: 50 }, model: 'gpt-4' })
      .mockResolvedValueOnce({ text: 'def exploit_v2(): pass', usage: { promptTokens: 100, completionTokens: 60 }, model: 'gpt-4' })
      .mockResolvedValueOnce({ text: 'def exploit_v3(): pass', usage: { promptTokens: 100, completionTokens: 70 }, model: 'gpt-4' });

    const candidates = await aiPoCGenerator.generateNBest({
      finding: { ruleId: 'r', title: 't', cwe: 'CWE-89' } as any,
      dataFlowPath: { source: 's', sinks: ['k'], path: [], sanitizers: [] },
      language: 'python',
      n: 3,
    });
    expect(candidates.length).toBe(3);
    expect(candidates[0].code).toContain('exploit_v1');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/poc/ai-generator-dfg.test.ts`
Expected: FAIL

- [ ] **Step 3: 修改 ai-poc-generator.ts**

在 [src/poc/ai-poc-generator.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/poc/ai-poc-generator.ts) 添加 DFG 感知:

```typescript
// 在 generatePoC 入口处, 增加 dataFlowPath 参数
export interface GenerateOptions {
  finding: { ruleId: string; title: string; cwe: string; severity?: string; codeSnippet?: string };
  dataFlowPath?: {
    source: string;
    sinks: string[];
    path: string[];          // 形如 'file.ts:line'
    sanitizers: string[];
  };
  language: string;
  projectContext?: { languages: string[]; frameworks: string[] };
}

export interface PoCCandidate {
  code: string;
  reasoning: string;
  score: number;            // 自评质量分
}

export const aiPoCGenerator = {
  /**
   * 单个 PoC 生成 (兼容旧 API)
   */
  async generate(opts: GenerateOptions): Promise<PoCCandidate> {
    const prompt = this.buildPrompt(opts);
    const { llmRouter } = await import('../llm/router.js');
    const result = await llmRouter.generateCompletion({
      prompt,
      model: 'gpt-4',
      maxTokens: 1500,
      temperature: 0.3,
    });

    // 用量埋点
    const { usageTracker } = await import('../billing/usage-tracker.js');
    const { getTenantContext } = await import('../auth/context.js');
    const ctx = getTenantContext();
    if (ctx && result.usage) {
      usageTracker.record({
        tenantId: ctx.tenantId,
        customerId: ctx.customerId || 'unknown',
        projectId: ctx.projectId,
        findingId: ctx.findingId,
        capability: 'ai_poc_generation',
        model: result.model,
        promptTokens: result.usage.promptTokens,
        completionTokens: result.usage.completionTokens,
      });
    }

    return {
      code: result.text,
      reasoning: '',
      score: 0.7,
    };
  },

  /**
   * N-best 候选生成 — 设计 §5.2 要求"AI 一次性生成 2-3 个不同思路"
   */
  async generateNBest(opts: GenerateOptions, n = 3): Promise<PoCCandidate[]> {
    const candidates: PoCCandidate[] = [];
    // 并发调用, 每路用不同 temperature 鼓励多样性
    const temps = [0.3, 0.6, 0.9];
    const { llmRouter } = await import('../llm/router.js');
    const { usageTracker } = await import('../billing/usage-tracker.js');
    const { getTenantContext } = await import('../auth/context.js');
    const ctx = getTenantContext();

    const results = await Promise.all(
      Array.from({ length: n }, (_, i) =>
        llmRouter.generateCompletion({
          prompt: this.buildPrompt(opts, { variant: i + 1, total: n }),
          model: 'gpt-4',
          maxTokens: 1500,
          temperature: temps[i] || 0.5,
        })
      ),
    );

    results.forEach((r, i) => {
      candidates.push({
        code: r.text,
        reasoning: `Variant ${i + 1}: temperature=${temps[i] || 0.5}`,
        score: 0.7 - i * 0.1,
      });
      if (ctx && r.usage) {
        usageTracker.record({
          tenantId: ctx.tenantId,
          customerId: ctx.customerId || 'unknown',
          projectId: ctx.projectId,
          findingId: ctx.findingId,
          capability: 'ai_poc_generation',
          model: r.model,
          promptTokens: r.usage.promptTokens,
          completionTokens: r.usage.completionTokens,
        });
      }
    });

    return candidates;
  },

  /**
   * 构建 prompt — 包含 DFG 数据流路径 (设计 §5.2)
   */
  buildPrompt(opts: GenerateOptions, meta: { variant: number; total: number } = { variant: 1, total: 1 }): string {
    const { finding, dataFlowPath, language, projectContext } = opts;
    const lines: string[] = [];

    lines.push(`You are a security expert. Generate a Proof-of-Concept exploit for the following vulnerability.`);
    lines.push(``);
    lines.push(`## Finding`);
    lines.push(`Rule: ${finding.ruleId}`);
    lines.push(`Title: ${finding.title}`);
    lines.push(`CWE: ${finding.cwe}`);
    lines.push(`Severity: ${finding.severity || 'unknown'}`);
    if (finding.codeSnippet) {
      lines.push(``);
      lines.push(`## Vulnerable Code`);
      lines.push('```' + language);
      lines.push(finding.codeSnippet);
      lines.push('```');
    }

    // === DFG 数据流感知 ===
    if (dataFlowPath) {
      lines.push(``);
      lines.push(`## Data Flow Path (DFG)`);
      lines.push(`Source (taint origin): ${dataFlowPath.source}`);
      lines.push(`Sinks (dangerous calls): ${dataFlowPath.sinks.join(', ')}`);
      lines.push(`Path:`);
      for (const hop of dataFlowPath.path) {
        lines.push(`  - ${hop}`);
      }
      if (dataFlowPath.sanitizers.length > 0) {
        lines.push(`Sanitizers (these were applied but may be bypassable): ${dataFlowPath.sanitizers.join(', ')}`);
      }
      lines.push(``);
      lines.push(`Use the data flow to construct a payload that traverses the path from source to sink.`);
    }

    if (projectContext) {
      lines.push(``);
      lines.push(`## Project Context`);
      lines.push(`Languages: ${projectContext.languages.join(', ')}`);
      lines.push(`Frameworks: ${projectContext.frameworks.join(', ')}`);
    }

    if (meta.total > 1) {
      lines.push(``);
      lines.push(`This is variant ${meta.variant} of ${meta.total}. Try a different attack angle.`);
    }

    lines.push(``);
    lines.push(`Output only the PoC code in a single code block, no explanation.`);
    return lines.join('\n');
  },
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/poc/ai-generator-dfg.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/poc/ai-poc-generator.ts tests/unit/poc/ai-generator-dfg.test.ts
git commit -m "feat(poc): DFG-aware AI PoC generator with N-best candidates per design §5.2"
```

---

## 任务 3: PoC 审核 AI 对话

**Files:**
- Create: `src/poc/poc-chat.ts`
- Test: `tests/unit/poc/poc-chat.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/poc/poc-chat.test.ts
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../src/llm/router', () => ({
  llmRouter: {
    generateCompletion: vi.fn().mockResolvedValue({
      text: 'PoC works because the input flows to db.query without sanitization.',
      usage: { promptTokens: 500, completionTokens: 100 },
      model: 'gpt-4',
    }),
  },
}));

import { pocChatService } from '../../../src/poc/poc-chat';

describe('pocChatService', () => {
  it('should answer engineer question about PoC', async () => {
    const answer = await pocChatService.ask({
      pocId: 'p1',
      code: 'def exploit(): pass',
      findingContext: { ruleId: 'sqli', cwe: 'CWE-89' },
      question: '这个 PoC 为什么能利用漏洞?',
    });
    expect(answer.text).toContain('db.query');
  });

  it('should support multi-turn conversation', async () => {
    const answer1 = await pocChatService.ask({
      pocId: 'p1', code: 'def x(): pass', findingContext: {} as any,
      question: 'first?',
    });
    const answer2 = await pocChatService.ask({
      pocId: 'p1', code: 'def x(): pass', findingContext: {} as any,
      question: 'second?',
      history: [{ role: 'user', content: 'first?' }, { role: 'assistant', content: answer1.text }],
    });
    expect(answer2.text).toBeDefined();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/poc/poc-chat.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 poc-chat.ts**

```typescript
// src/poc/poc-chat.ts
/**
 * PoC 审核 AI 对话 — 对齐设计 §5.2 "AI 对话(追问)"
 */
import { childLogger } from '../utils/logger.js';

const logger = childLogger('poc-chat');

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface ChatInput {
  pocId: string;
  code: string;
  findingContext: { ruleId: string; cwe?: string; title?: string };
  question: string;
  history?: ChatMessage[];
}

export interface ChatAnswer {
  text: string;
  tokensUsed: number;
}

export const pocChatService = {
  async ask(input: ChatInput): Promise<ChatAnswer> {
    const { llmRouter } = await import('../llm/router.js');
    const { usageTracker } = await import('../billing/usage-tracker.js');
    const { getTenantContext } = await import('../auth/context.js');

    const messages: ChatMessage[] = [
      {
        role: 'user',
        content: `You are a security expert helping an engineer review a PoC for: ${input.findingContext.ruleId} (${input.findingContext.cwe || 'N/A'}).

PoC code:
\`\`\`
${input.code}
\`\`\`

Answer concisely and accurately in the same language the engineer uses.`,
      },
      ...(input.history || []),
      { role: 'user', content: input.question },
    ];

    // 构造 prompt (简化为 single-prompt 而非 multi-message, 兼容性更好)
    const prompt = messages.map((m) => `${m.role === 'user' ? 'Human' : 'Assistant'}: ${m.content}`).join('\n\n') + '\n\nAssistant:';

    const result = await llmRouter.generateCompletion({
      prompt,
      model: 'gpt-4',
      maxTokens: 500,
      temperature: 0.4,
    });

    // 埋点
    const ctx = getTenantContext();
    if (ctx && result.usage) {
      usageTracker.record({
        tenantId: ctx.tenantId,
        customerId: ctx.customerId || 'unknown',
        projectId: ctx.projectId,
        findingId: ctx.findingId,
        capability: 'ai_explain',
        model: result.model,
        promptTokens: result.usage.promptTokens,
        completionTokens: result.usage.completionTokens,
      });
    }

    return {
      text: result.text.trim(),
      tokensUsed: (result.usage?.promptTokens || 0) + (result.usage?.completionTokens || 0),
    };
  },
};
```

- [ ] **Step 4: 在 poc-router.ts 添加 chat 端点**

在 [src/poc/poc-router.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/poc/poc-router.ts) 添加:

```typescript
import { pocChatService } from './poc-chat.js';

router.post('/pocs/:id/chat', async (req, res) => {
  try {
    const poc = pocManager.get(req.params.id);
    if (!poc) return res.status(404).json({ error: 'PoC not found' });
    const { question, history } = req.body;
    const answer = await pocChatService.ask({
      pocId: poc.id,
      code: poc.code,
      findingContext: { ruleId: poc.ruleId, cwe: poc.cwe, title: poc.title },
      question,
      history,
    });
    res.json({ success: true, data: answer });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/poc/poc-chat.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/poc/poc-chat.ts src/poc/poc-router.ts tests/unit/poc/poc-chat.test.ts
git commit -m "feat(poc): AI chat assistance for PoC review per design §5.2"
```

---

## 任务 4: GitLab Issues 集成

**Files:**
- Create: `src/integrations/gitlab-issues.ts`
- Test: `tests/unit/integrations/gitlab-issues.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/integrations/gitlab-issues.test.ts
import { describe, it, expect, vi } from 'vitest';
import { GitLabIssues } from '../../../src/integrations/gitlab-issues';

vi.mock('../../../src/utils/http-client', () => ({
  httpClient: {
    post: vi.fn().mockResolvedValue({ data: { iid: 42, web_url: 'https://gitlab.com/a/b/-/issues/42' } }),
    put: vi.fn().mockResolvedValue({ data: {} }),
  },
}));

describe('GitLabIssues', () => {
  it('should create an issue', async () => {
    const gl = new GitLabIssues({ instanceUrl: 'https://gitlab.com', token: 't' });
    const issue = await gl.create({
      projectPath: 'acme/web',
      title: '[CRITICAL] SQL Injection in checkout.ts',
      description: '## Detail\nVulnerable code: ...',
      labels: ['security', 'critical'],
    });
    expect(issue.iid).toBe(42);
    expect(issue.url).toContain('issues/42');
  });

  it('should update issue status (close)', async () => {
    const gl = new GitLabIssues({ instanceUrl: 'https://gitlab.com', token: 't' });
    await gl.close({ projectPath: 'acme/web', iid: 42 });
    // 验证 PUT 调用 state_event=close
    const { httpClient } = await import('../../../src/utils/http-client');
    expect(httpClient.put).toHaveBeenCalledWith(
      expect.stringContaining('state_event=close'),
      expect.anything(),
      expect.anything(),
    );
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/integrations/gitlab-issues.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 gitlab-issues.ts**

```typescript
// src/integrations/gitlab-issues.ts
/**
 * GitLab Issues 集成 — 对齐设计 §6.4
 */
import { httpClient } from '../utils/http-client.js';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('gitlab-issues');

export interface GitLabConfig {
  instanceUrl: string;
  token: string;
}

export interface CreateIssueInput {
  projectPath: string;
  title: string;
  description: string;
  labels?: string[];
  confidential?: boolean;
}

export interface CreatedIssue {
  iid: number;
  url: string;
}

export class GitLabIssues {
  constructor(private config: GitLabConfig) {}

  private get baseUrl(): string {
    return `${this.config.instanceUrl.replace(/\/$/, '')}/api/v4`;
  }

  private get headers(): Record<string, string> {
    return { 'PRIVATE-TOKEN': this.config.token };
  }

  async create(input: CreateIssueInput): Promise<CreatedIssue> {
    const encoded = encodeURIComponent(input.projectPath);
    const { data } = await httpClient.post(
      `${this.baseUrl}/projects/${encoded}/issues`,
      {
        title: input.title,
        description: input.description,
        labels: (input.labels || []).join(','),
        confidential: input.confidential || false,
      },
      { headers: this.headers },
    );
    logger.info('GitLab issue created', { project: input.projectPath, iid: data.iid });
    return { iid: data.iid, url: data.web_url };
  }

  async comment(input: { projectPath: string; iid: number; body: string }): Promise<void> {
    const encoded = encodeURIComponent(input.projectPath);
    await httpClient.post(
      `${this.baseUrl}/projects/${encoded}/issues/${input.iid}/notes`,
      { body: input.body },
      { headers: this.headers },
    );
  }

  async close(input: { projectPath: string; iid: number }): Promise<void> {
    const encoded = encodeURIComponent(input.projectPath);
    await httpClient.put(
      `${this.baseUrl}/projects/${encoded}/issues/${input.iid}?state_event=close`,
      {},
      { headers: this.headers },
    );
    logger.info('GitLab issue closed', { project: input.projectPath, iid: input.iid });
  }
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/integrations/gitlab-issues.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/integrations/gitlab-issues.ts tests/unit/integrations/gitlab-issues.test.ts
git commit -m "feat(integrations): GitLab Issues integration (create/comment/close) per design §6.4"
```

---

## 任务 5: Jira 集成

**Files:**
- Create: `src/integrations/jira.ts`
- Test: `tests/unit/integrations/jira.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/integrations/jira.test.ts
import { describe, it, expect, vi } from 'vitest';
import { JiraIntegration } from '../../../src/integrations/jira';

vi.mock('../../../src/utils/http-client', () => ({
  httpClient: {
    post: vi.fn().mockResolvedValue({ data: { key: 'SEC-123' } }),
    put: vi.fn().mockResolvedValue({ data: {} }),
  },
}));

describe('JiraIntegration', () => {
  it('should create issue with security fields', async () => {
    const j = new JiraIntegration({ host: 'https://acme.atlassian.net', email: 'a@b.com', apiToken: 't' });
    const issue = await j.create({
      projectKey: 'SEC',
      issueType: 'Bug',
      summary: '[CRITICAL] SQL Injection',
      description: '## Detail\n...',
      priority: 'Highest',
      labels: ['security-vule', 'critical'],
    });
    expect(issue.key).toBe('SEC-123');
  });

  it('should transition issue to Done', async () => {
    const j = new JiraIntegration({ host: 'https://acme.atlassian.net', email: 'a@b.com', apiToken: 't' });
    await j.transition({ issueKey: 'SEC-123', transitionName: 'Done' });
    const { httpClient } = await import('../../../src/utils/http-client');
    expect(httpClient.post).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/integrations/jira.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 jira.ts**

```typescript
// src/integrations/jira.ts
/**
 * Jira 集成 — 对齐设计 §6.4 (Jira Cloud REST API v3)
 */
import { httpClient } from '../utils/http-client.js';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('jira');

export interface JiraConfig {
  host: string;            // e.g. https://acme.atlassian.net
  email: string;
  apiToken: string;
}

export interface CreateJiraInput {
  projectKey: string;
  issueType: string;
  summary: string;
  description: string;
  priority?: string;
  labels?: string[];
  assigneeAccountId?: string;
}

export interface CreatedJira {
  key: string;
  url: string;
}

export class JiraIntegration {
  constructor(private config: JiraConfig) {}

  private get authHeader(): string {
    const raw = `${this.config.email}:${this.config.apiToken}`;
    return `Basic ${Buffer.from(raw).toString('base64')}`;
  }

  private get baseUrl(): string {
    return `${this.config.host.replace(/\/$/, '')}/rest/api/3`;
  }

  async create(input: CreateJiraInput): Promise<CreatedJira> {
    const { data } = await httpClient.post(
      `${this.baseUrl}/issue`,
      {
        fields: {
          project: { key: input.projectKey },
          issuetype: { name: input.issueType },
          summary: input.summary,
          description: {
            type: 'doc',
            version: 1,
            content: [{ type: 'paragraph', content: [{ type: 'text', text: input.description }] }],
          },
          priority: input.priority ? { name: input.priority } : undefined,
          labels: input.labels,
          assignee: input.assigneeAccountId ? { accountId: input.assigneeAccountId } : undefined,
        },
      },
      {
        headers: {
          Authorization: this.authHeader,
          'Content-Type': 'application/json',
        },
      },
    );
    logger.info('Jira issue created', { key: data.key });
    return {
      key: data.key,
      url: `${this.config.host}/browse/${data.key}`,
    };
  }

  async comment(input: { issueKey: string; body: string }): Promise<void> {
    await httpClient.post(
      `${this.baseUrl}/issue/${input.issueKey}/comment`,
      {
        body: {
          type: 'doc',
          version: 1,
          content: [{ type: 'paragraph', content: [{ type: 'text', text: input.body }] }],
        },
      },
      { headers: { Authorization: this.authHeader, 'Content-Type': 'application/json' } },
    );
  }

  async transition(input: { issueKey: string; transitionName: string }): Promise<void> {
    // 1. 获取 transition id
    const { data } = await httpClient.get(
      `${this.baseUrl}/issue/${input.issueKey}/transitions`,
      { headers: { Authorization: this.authHeader } },
    );
    const t = data.transitions.find((x: any) => x.name === input.transitionName);
    if (!t) throw new Error(`Jira transition not found: ${input.transitionName}`);

    // 2. 执行 transition
    await httpClient.post(
      `${this.baseUrl}/issue/${input.issueKey}/transitions`,
      { transition: { id: t.id } },
      { headers: { Authorization: this.authHeader, 'Content-Type': 'application/json' } },
    );
  }
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/integrations/jira.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/integrations/jira.ts tests/unit/integrations/jira.test.ts
git commit -m "feat(integrations): Jira Cloud integration (create/comment/transition) per design §6.4"
```

---

## 任务 6: 单 Finding PDF 报告

**Files:**
- Create: `src/report/report-pdf.ts`
- Test: `tests/unit/report/report-pdf.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/report/report-pdf.test.ts
import { describe, it, expect } from 'vitest';
import { reportPdfGenerator } from '../../../src/report/report-pdf';

describe('ReportPdfGenerator', () => {
  it('should render single finding report', async () => {
    const pdf = await reportPdfGenerator.renderFindingReport({
      findingId: 'F-001',
      title: 'SQL Injection in checkout.ts',
      severity: 'CRITICAL',
      status: 'confirmed',
      ruleId: 'sqli-001',
      cwe: 'CWE-89',
      file: 'src/checkout.ts',
      line: 42,
      codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
      dataFlow: 'req.body.id → controller → query',
      pocCode: 'def exploit(): payload = "1\' OR 1=1--"; ...',
      pocResult: { success: true, output: 'Vulnerability confirmed' },
      fixSuggestion: 'Use parameterized queries.',
      generatedAt: '2026-01-01T00:00:00Z',
    });
    expect(pdf).toBeInstanceOf(Buffer);
    expect(pdf.slice(0, 4).toString()).toBe('%PDF');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/report/report-pdf.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 report-pdf.ts**

```typescript
// src/report/report-pdf.ts
/**
 * 单 Finding 报告 PDF 生成 — 对齐设计 §5.4 "可复现报告"
 */
import PDFDocument from 'pdfkit';

export interface FindingReportInput {
  findingId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: string;
  ruleId: string;
  cwe: string;
  file: string;
  line: number;
  codeSnippet: string;
  dataFlow?: string;
  pocCode?: string;
  pocResult?: { success: boolean; output: string };
  fixSuggestion?: string;
  generatedAt: string;
  logoBase64?: string;
  watermark?: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#D13438',
  HIGH: '#F7630C',
  MEDIUM: '#FFB900',
  LOW: '#008272',
  INFO: '#5C6BC0',
};

export const reportPdfGenerator = {
  async renderFindingReport(input: FindingReportInput): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50, size: 'A4' });
        const chunks: Buffer[] = [];
        doc.on('data', (c: Buffer) => chunks.push(c));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        // 标题区
        doc.rect(50, 50, 500, 30).fill(SEVERITY_COLOR[input.severity]);
        doc.fillColor('white').fontSize(16).text(
          `${input.severity}  ${input.title}`,
          60, 58, { width: 480, height: 20 }
        );
        doc.fillColor('black');
        doc.moveDown(2);

        // 元数据表
        doc.fontSize(10);
        doc.text(`Finding ID: ${input.findingId}     Status: ${input.status}     Generated: ${input.generatedAt}`);
        doc.text(`Rule: ${input.ruleId}     CWE: ${input.cwe}`);
        doc.text(`File: ${input.file}:${input.line}`);
        doc.moveDown();

        // 漏洞代码
        doc.fontSize(12).font('Helvetica-Bold').text('Vulnerable Code');
        doc.font('Courier').fontSize(9);
        doc.text(input.codeSnippet, { width: 500 });
        doc.font('Helvetica');
        doc.moveDown();

        // DFG 数据流
        if (input.dataFlow) {
          doc.fontSize(12).font('Helvetica-Bold').text('Data Flow Path');
          doc.font('Helvetica').fontSize(10);
          doc.text(input.dataFlow);
          doc.moveDown();
        }

        // PoC
        if (input.pocCode) {
          doc.fontSize(12).font('Helvetica-Bold').text('PoC Verification');
          doc.font('Helvetica').fontSize(10);
          if (input.pocResult?.success) {
            doc.fillColor('#008272').text('✓ Confirmed: Vulnerability is exploitable');
            doc.fillColor('black');
          } else {
            doc.fillColor('#D13438').text('✗ Failed: Could not confirm exploitability');
            doc.fillColor('black');
          }
          doc.font('Courier').fontSize(8);
          doc.text(input.pocCode, { width: 500 });
          doc.font('Helvetica');
          doc.moveDown();
        }

        // 修复建议
        if (input.fixSuggestion) {
          doc.fontSize(12).font('Helvetica-Bold').text('Fix Suggestion');
          doc.font('Helvetica').fontSize(10);
          doc.text(input.fixSuggestion, { width: 500 });
          doc.moveDown();
        }

        // 水印
        if (input.watermark) {
          doc.opacity(0.08);
          doc.fontSize(72).fillColor('#888').text(
            input.watermark, 0, 400, { align: 'center', width: 600 }
          );
          doc.opacity(1);
        }

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  },
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/report/report-pdf.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/report/report-pdf.ts tests/unit/report/report-pdf.test.ts
git commit -m "feat(report): single Finding PDF report with DFG and PoC per design §5.4"
```

---

## 任务 7: 周报聚合

**Files:**
- Create: `src/report/weekly-report.ts`
- Test: 单元测试内嵌

- [ ] **Step 1: 实现 weekly-report.ts**

```typescript
// src/report/weekly-report.ts
/**
 * 周报聚合 — 对齐设计 §6.5
 */
import { childLogger } from '../utils/logger.js';

const logger = childLogger('weekly-report');

export interface FindingForReport {
  id: string;
  severity: string;
  status: string;
  ruleId: string;
  title: string;
  customerId: string;
  createdAt: number;
  fixedAt?: number;
}

export interface WeeklyReportData {
  periodStart: string;
  periodEnd: string;
  customerId?: string;       // null = 服务商全局
  
  newFindings: number;
  fixedFindings: number;
  regressedFindings: number;
  bySeverity: Record<string, { newCount: number; fixedCount: number }>;
  topVulns: Array<{ ruleId: string; title: string; count: number }>;
  aiTokenUsage: number;
  pocVerifiedCount: number;
}

export const weeklyReportService = {
  generate(input: {
    periodStart: number;
    periodEnd: number;
    customerId?: string;
    findings: FindingForReport[];
    aiTokens: number;
  }): WeeklyReportData {
    const { periodStart, periodEnd, customerId, findings, aiTokens } = input;
    const periodMs = input.periodEnd - input.periodStart;

    const newFindings = findings.filter((f) => f.createdAt >= periodStart && f.createdAt <= periodEnd);
    const fixedFindings = findings.filter(
      (f) => f.fixedAt && f.fixedAt >= periodStart && f.fixedAt <= periodEnd
    );
    const regressedFindings = findings.filter(
      (f) => f.status === 'regressed' && f.createdAt >= periodStart && f.createdAt <= periodEnd
    );

    // 按严重度统计
    const bySeverity: WeeklyReportData['bySeverity'] = {};
    for (const f of newFindings) {
      if (!bySeverity[f.severity]) bySeverity[f.severity] = { newCount: 0, fixedCount: 0 };
      bySeverity[f.severity].newCount++;
    }
    for (const f of fixedFindings) {
      if (!bySeverity[f.severity]) bySeverity[f.severity] = { newCount: 0, fixedCount: 0 };
      bySeverity[f.severity].fixedCount++;
    }

    // Top 漏洞
    const ruleCount = new Map<string, { title: string; count: number }>();
    for (const f of newFindings) {
      const existing = ruleCount.get(f.ruleId) || { title: f.title, count: 0 };
      existing.count++;
      ruleCount.set(f.ruleId, existing);
    }
    const topVulns = Array.from(ruleCount.entries())
      .map(([ruleId, v]) => ({ ruleId, title: v.title, count: v.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      periodStart: new Date(periodStart).toISOString(),
      periodEnd: new Date(periodEnd).toISOString(),
      customerId,
      newFindings: newFindings.length,
      fixedFindings: fixedFindings.length,
      regressedFindings: regressedFindings.length,
      bySeverity,
      topVulns,
      aiTokenUsage: aiTokens,
      pocVerifiedCount: newFindings.filter((f) => f.status === 'confirmed').length,
    };
  },
};
```

- [ ] **Step 2: 提交**

```bash
git add src/report/weekly-report.ts
git commit -m "feat(report): weekly report aggregation per design §6.5"
```

---

## 任务 8: 验收

```bash
bun run test tests/unit/finding/ tests/unit/poc/ tests/unit/integrations/ tests/unit/report/
```

```bash
git add -A
git commit -m "chore: phase1 P2 PoC sandbox and collaboration complete

- Finding 8-state machine (regressed/escalated)
- DFG-aware PoC generation with N-best candidates
- AI chat for PoC review
- GitLab Issues integration
- Jira Cloud integration
- Single Finding PDF report
- Weekly report aggregation"
```

## 执行选项

**1. 子代理驱动 (推荐)**
**2. 内联执行**

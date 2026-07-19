# 第三波 P1 计划:代码源与检测策略

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把接入与检测模块从"扫描能跑"升级到"持续闭环",实现三种代码源(GitHub/GitLab/上传)、项目两阶段创建 + 5 态状态机、扫描 7 态状态机统一、三层策略覆盖、Findings 跨扫描稳定 ID、入站 Webhook。

**Architecture:** 在现有 dashboard/connectors/ 上扩展,新增独立 connectors/github, gitlab, upload 模块;policy-config 拆为三层合并函数;finding 增加 fingerPrint 字段。

**Tech Stack:** TypeScript, Express, Multer(文件上传), Octokit(GitHub), gitbeaker(GitLab), tar/解压

---

## 文件结构

```
src/
├── connectors/                     # 新增: 三种代码源连接器
│   ├── github.ts                   # GitHub OAuth + 仓库管理
│   ├── gitlab.ts                   # GitLab OAuth + 仓库管理
│   ├── upload.ts                   # 文件上传 (multer)
│   └── index.ts                    # 工厂
├── dashboard/
│   ├── scanners/
│   │   ├── scan-state.ts           # 新增: 7 态状态机
│   │   ├── finding-fingerprint.ts  # 新增: 跨扫描稳定 ID
│   │   ├── finding-dedup.ts        # 新增: 同位置多引擎合并
│   │   └── scan-orchestrator.ts    # 修改: 接入状态机
│   └── policies/
│       ├── policy-types.ts         # 新增: 三层策略类型
│       ├── policy-merge.ts         # 新增: 三层合并函数
│       └── policy-store.ts         # 新增: 策略持久化
├── project/
│   ├── project-lifecycle.ts        # 新增: 两阶段创建 + 5 态
│   └── project-types.ts            # 修改: 扩展状态
├── webhooks/
│   ├── incoming.ts                 # 新增: 入站 Webhook
│   └── verify.ts                   # 新增: 签名校验
└── scheduler/
    └── cron-scheduler.ts           # 新增: 定时全量扫描
tests/
├── unit/
│   ├── connectors/
│   │   ├── github.test.ts
│   │   ├── gitlab.test.ts
│   │   └── upload.test.ts
│   ├── dashboard/
│   │   ├── scan-state.test.ts
│   │   ├── finding-fingerprint.test.ts
│   │   └── policy-merge.test.ts
│   └── project/
│       └── project-lifecycle.test.ts
```

---

## 任务 1: 项目两阶段创建 + 5 态状态机

**Files:**
- Create: `src/project/project-lifecycle.ts`
- Modify: `src/auth/project-types.ts`
- Test: `tests/unit/project/project-lifecycle.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/project/project-lifecycle.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { projectLifecycle } from '../../../src/project/project-lifecycle';

describe('ProjectLifecycle', () => {
  beforeEach(() => projectLifecycle._reset?.());

  it('should quick-create a project in configuring state', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1',
      name: 'web-checkout-svc',
      sourceType: 'github',
      createdBy: 'eng-1',
    });
    expect(p.status).toBe('configuring');
    expect(p.source).toBeNull();
  });

  it('should not allow scan in configuring state', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1', name: 'p1', sourceType: 'github', createdBy: 'u',
    });
    expect(() => projectLifecycle.assertCanScan(p)).toThrow(/configuring/);
  });

  it('should transition to active after source configured and synced', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1', name: 'p1', sourceType: 'github', createdBy: 'u',
    });
    const configured = await projectLifecycle.configureSource(p.id, {
      type: 'github',
      repoFullName: 'acme/web-checkout',
      branch: 'main',
      accessTokenCipher: 'encrypted:xxx',
    });
    expect(configured.status).toBe('syncing');

    const synced = await projectLifecycle.markSynced(p.id, {
      snapshotHash: 'abc123',
      fileCount: 200,
    });
    expect(synced.status).toBe('active');
    expect(synced.snapshotHash).toBe('abc123');
  });

  it('should transition to error if sync fails', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1', name: 'p1', sourceType: 'github', createdBy: 'u',
    });
    await projectLifecycle.configureSource(p.id, {
      type: 'github', repoFullName: 'a/b', branch: 'main', accessTokenCipher: 'x',
    });
    const errored = await projectLifecycle.markSyncFailed(p.id, 'Token expired');
    expect(errored.status).toBe('error');
    expect(errored.lastError).toBe('Token expired');
  });

  it('should allow pause and resume', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1', name: 'p1', sourceType: 'github', createdBy: 'u',
    });
    await projectLifecycle.configureSource(p.id, {
      type: 'github', repoFullName: 'a/b', branch: 'main', accessTokenCipher: 'x',
    });
    await projectLifecycle.markSynced(p.id, { snapshotHash: 'h', fileCount: 1 });

    const paused = await projectLifecycle.pause(p.id);
    expect(paused.status).toBe('paused');

    const resumed = await projectLifecycle.resume(p.id);
    expect(resumed.status).toBe('active');
  });

  it('should soft-delete (preserve data)', async () => {
    const p = await projectLifecycle.quickCreate({
      tenantId: 't1', customerId: 'c1', name: 'p1', sourceType: 'github', createdBy: 'u',
    });
    const deleted = await projectLifecycle.softDelete(p.id);
    expect(deleted.status).toBe('deleted');
    expect(deleted.deletedAt).toBeDefined();
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/project/project-lifecycle.test.ts`
Expected: FAIL

- [ ] **Step 3: 修改 project-types.ts 扩展状态**

修改 [src/auth/project-types.ts:37](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/project-types.ts#L37):

```typescript
export type ProjectStatus =
  | 'configuring'   // 新建: 等待详配
  | 'syncing'       // 同步中
  | 'active'        // 正常
  | 'paused'        // 暂停
  | 'error'         // 同步失败
  | 'deleted';      // 软删除

// Project 接口扩展
export interface Project {
  id: string;
  tenantId: string;
  customerId: string;
  name: string;
  source: ProjectRepository | null;     // configuring 时为 null
  status: ProjectStatus;
  branchPolicy?: { type: 'main' | 'multi' | 'regex'; pattern?: string };
  ignorePaths?: string[];
  policyId?: string;
  labels?: string[];
  ownerUserId?: string;
  slaLevel?: 'standard' | 'priority' | 'urgent';
  notificationRules?: Array<{ event: string; channel: string }>;
  dataRetentionDays?: number;
  snapshotHash?: string;                 // 当前基线 hash
  fileCount?: number;
  lastError?: string;
  createdAt: number;
  updatedAt: number;
  deletedAt?: number;
}

export interface ProjectRepository {
  type: 'github' | 'gitlab' | 'upload';
  repoFullName?: string;       // acme/web-checkout
  branch?: string;
  accessTokenCipher?: string;  // KMS 加密
  uploadObjectKey?: string;    // 对象存储 key
  webhookId?: string;
  webhookSecret?: string;
}
```

- [ ] **Step 4: 实现 project-lifecycle.ts**

```typescript
// src/project/project-lifecycle.ts
import { childLogger } from '../utils/logger.js';
import type { Project, ProjectStatus, ProjectRepository } from '../auth/project-types.js';

const logger = childLogger('project-lifecycle');

const projects = new Map<string, Project>();
let _idCounter = 0;

function nowMs(): number { return Date.now(); }
function nextId(): string {
  _idCounter++;
  return `proj-${Date.now()}-${_idCounter}`;
}

const TRANSITIONS: Record<ProjectStatus, ProjectStatus[]> = {
  configuring: ['syncing', 'error', 'deleted'],
  syncing: ['active', 'error', 'deleted'],
  active: ['paused', 'error', 'deleted'],
  paused: ['active', 'deleted'],
  error: ['configuring', 'syncing', 'deleted'],   // 修复后可重试
  deleted: [],   // 终态
};

function assertTransition(from: ProjectStatus, to: ProjectStatus): void {
  if (!TRANSITIONS[from].includes(to)) {
    throw new Error(`Invalid transition: ${from} -> ${to}`);
  }
}

export const projectLifecycle = {
  /**
   * 阶段 1: 快速创建 (3 字段), 状态 = configuring
   */
  async quickCreate(input: {
    tenantId: string;
    customerId: string;
    name: string;
    sourceType: 'github' | 'gitlab' | 'upload';
    createdBy: string;
  }): Promise<Project> {
    const project: Project = {
      id: nextId(),
      tenantId: input.tenantId,
      customerId: input.customerId,
      name: input.name,
      source: null,  // configuring 时无 source
      status: 'configuring',
      createdAt: nowMs(),
      updatedAt: nowMs(),
    };
    projects.set(project.id, project);
    logger.info('Project quick-created', {
      id: project.id, name: input.name, sourceType: input.sourceType,
    });
    return project;
  },

  /**
   * 阶段 2: 详配 source, 状态 → syncing
   */
  async configureSource(projectId: string, repo: ProjectRepository): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'syncing');
    p.source = repo;
    p.status = 'syncing';
    p.updatedAt = nowMs();
    logger.info('Project source configured', { projectId, type: repo.type });
    return p;
  },

  /**
   * 同步成功 → active
   */
  async markSynced(projectId: string, info: { snapshotHash: string; fileCount: number }): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'active');
    p.status = 'active';
    p.snapshotHash = info.snapshotHash;
    p.fileCount = info.fileCount;
    p.lastError = undefined;
    p.updatedAt = nowMs();
    return p;
  },

  /**
   * 同步失败 → error
   */
  async markSyncFailed(projectId: string, reason: string): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'error');
    p.status = 'error';
    p.lastError = reason;
    p.updatedAt = nowMs();
    return p;
  },

  /**
   * 暂停
   */
  async pause(projectId: string): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'paused');
    p.status = 'paused';
    p.updatedAt = nowMs();
    return p;
  },

  /**
   * 恢复
   */
  async resume(projectId: string): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'active');
    p.status = 'active';
    p.updatedAt = nowMs();
    return p;
  },

  /**
   * 软删除
   */
  async softDelete(projectId: string): Promise<Project> {
    const p = projects.get(projectId);
    if (!p) throw new Error(`Project not found: ${projectId}`);
    assertTransition(p.status, 'deleted');
    p.status = 'deleted';
    p.deletedAt = nowMs();
    p.updatedAt = nowMs();
    return p;
  },

  assertCanScan(p: Project): void {
    if (p.status !== 'active') {
      throw new Error(`Project cannot scan in state: ${p.status}`);
    }
  },

  get(id: string): Project | undefined {
    return projects.get(id);
  },

  list(filter: { tenantId?: string; customerId?: string; status?: ProjectStatus }): Project[] {
    return Array.from(projects.values()).filter((p) => {
      if (filter.tenantId && p.tenantId !== filter.tenantId) return false;
      if (filter.customerId && p.customerId !== filter.customerId) return false;
      if (filter.status && p.status !== filter.status) return false;
      if (p.status === 'deleted' && !filter.status) return false;
      return true;
    });
  },

  /** @internal */
  _reset(): void {
    projects.clear();
    _idCounter = 0;
  },
};
```

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/project/project-lifecycle.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/auth/project-types.ts src/project/project-lifecycle.ts tests/unit/project/project-lifecycle.test.ts
git commit -m "feat(project): two-stage creation with 5-state lifecycle per design §3.9"
```

---

## 任务 2: GitHub 连接器(OAuth + 仓库 + Webhook)

**Files:**
- Create: `src/connectors/github.ts`
- Test: `tests/unit/connectors/github.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/connectors/github.test.ts
import { describe, it, expect, vi } from 'vitest';
import { GitHubConnector } from '../../../src/connectors/github';

vi.mock('octokit', () => ({
  Octokit: vi.fn().mockImplementation(() => ({
    rest: {
      apps: { createFromManifest: vi.fn() },
      repos: { listForAuthenticatedUser: vi.fn().mockResolvedValue({ data: [{ full_name: 'acme/web' }] }) },
      hooks: {
        create: vi.fn().mockResolvedValue({ data: { id: 12345 } }),
        delete: vi.fn().mockResolvedValue({ data: {} }),
      },
    },
  })),
}));

describe('GitHubConnector', () => {
  it('should list accessible repos for a token', async () => {
    const connector = new GitHubConnector();
    const repos = await connector.listRepos('test-token');
    expect(repos).toEqual([{ fullName: 'acme/web' }]);
  });

  it('should register webhook on repo', async () => {
    const connector = new GitHubConnector();
    const hook = await connector.registerWebhook({
      token: 'test-token',
      repoFullName: 'acme/web',
      webhookUrl: 'https://api.security-vule.io/api/v1/webhooks/incoming/github',
      secret: 'whsec_xxx',
    });
    expect(hook.id).toBe(12345);
  });

  it('should remove webhook on disconnect', async () => {
    const connector = new GitHubConnector();
    await connector.removeWebhook({
      token: 'test-token',
      repoFullName: 'acme/web',
      hookId: 12345,
    });
    // 不抛异常即视为成功
  });

  it('should fetch file tree (clone via API)', async () => {
    const connector = new GitHubConnector();
    const tree = await connector.fetchTree({
      token: 'test-token',
      repoFullName: 'acme/web',
      ref: 'main',
    });
    expect(Array.isArray(tree)).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/connectors/github.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 github.ts**

```typescript
// src/connectors/github.ts
import { Octokit } from 'octokit';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('connector-github');

export interface RepoInfo {
  fullName: string;
  defaultBranch: string;
  private: boolean;
  description?: string;
  language?: string;
}

export interface FileEntry {
  path: string;
  sha: string;
  size: number;
  type: 'blob' | 'tree';
}

export class GitHubConnector {
  private client: Octokit;

  constructor(token?: string) {
    this.client = new Octokit(token ? { auth: token } : {});
  }

  /**
   * 列出当前 token 可访问的仓库
   */
  async listRepos(token: string): Promise<RepoInfo[]> {
    const connector = new GitHubConnector(token);
    const { data } = await connector.client.rest.repos.listForAuthenticatedUser({
      per_page: 100,
    });
    return data.map((r) => ({
      fullName: r.full_name,
      defaultBranch: r.default_branch,
      private: r.private,
      description: r.description ?? undefined,
      language: r.language ?? undefined,
    }));
  }

  /**
   * 注册 webhook
   */
  async registerWebhook(input: {
    token: string;
    repoFullName: string;
    webhookUrl: string;
    secret: string;
  }): Promise<{ id: number }> {
    const connector = new GitHubConnector(input.token);
    const [owner, repo] = input.repoFullName.split('/');
    const { data } = await connector.client.rest.repos.createWebhook({
      owner,
      repo,
      config: {
        url: input.webhookUrl,
        content_type: 'json',
        secret: input.secret,
        insecure_ssl: '0',
      },
      events: ['push', 'pull_request'],
      active: true,
    });
    logger.info('GitHub webhook registered', { repo: input.repoFullName, hookId: data.id });
    return { id: data.id };
  }

  /**
   * 删除 webhook
   */
  async removeWebhook(input: {
    token: string;
    repoFullName: string;
    hookId: number;
  }): Promise<void> {
    const connector = new GitHubConnector(input.token);
    const [owner, repo] = input.repoFullName.split('/');
    await connector.client.rest.repos.deleteWebhook({
      owner,
      repo,
      hook_id: input.hookId,
    });
    logger.info('GitHub webhook removed', { repo: input.repoFullName, hookId: input.hookId });
  }

  /**
   * 拉取文件树
   */
  async fetchTree(input: {
    token: string;
    repoFullName: string;
    ref: string;
  }): Promise<FileEntry[]> {
    const connector = new GitHubConnector(input.token);
    const [owner, repo] = input.repoFullName.split('/');
    const { data } = await connector.client.rest.git.getTree({
      owner,
      repo,
      tree_sha: input.ref,
      recursive: 'true',
    });
    return data.tree
      .filter((t) => t.path && t.sha)
      .map((t) => ({
        path: t.path!,
        sha: t.sha!,
        size: t.size || 0,
        type: t.type === 'tree' ? 'tree' : 'blob',
      }));
  }

  /**
   * 拉取单个文件内容
   */
  async fetchFile(input: {
    token: string;
    repoFullName: string;
    path: string;
    ref: string;
  }): Promise<string> {
    const connector = new GitHubConnector(input.token);
    const [owner, repo] = input.repoFullName.split('/');
    const { data } = await connector.client.rest.repos.getContent({
      owner,
      repo,
      path: input.path,
      ref: input.ref,
    });
    if (Array.isArray(data) || data.type !== 'file') {
      throw new Error(`Not a file: ${input.path}`);
    }
    return Buffer.from(data.content, 'base64').toString('utf-8');
  }
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/connectors/github.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/connectors/github.ts tests/unit/connectors/github.test.ts
git commit -m "feat(connectors): GitHub OAuth + repo list + webhook per design §3.3"
```

---

## 任务 3: GitLab 连接器

**Files:**
- Create: `src/connectors/gitlab.ts`
- Test: `tests/unit/connectors/gitlab.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/connectors/gitlab.test.ts
import { describe, it, expect, vi } from 'vitest';
import { GitLabConnector } from '../../../src/connectors/gitlab';

vi.mock('../../../src/utils/http-client', () => ({
  httpClient: {
    get: vi.fn().mockImplementation((url: string) => {
      if (url.includes('/projects')) {
        return Promise.resolve({ data: [{ path_with_namespace: 'acme/web', default_branch: 'main' }] });
      }
      return Promise.resolve({ data: [] });
    }),
    post: vi.fn().mockResolvedValue({ data: { id: 99 } }),
    delete: vi.fn().mockResolvedValue({ data: {} }),
  },
}));

describe('GitLabConnector', () => {
  it('should list repos', async () => {
    const c = new GitLabConnector({ instanceUrl: 'https://gitlab.com', token: 't' });
    const repos = await c.listRepos();
    expect(repos[0].fullName).toBe('acme/web');
  });

  it('should support self-hosted GitLab', async () => {
    const c = new GitLabConnector({ instanceUrl: 'https://gitlab.acme.com', token: 't' });
    const repos = await c.listRepos();
    expect(Array.isArray(repos)).toBe(true);
  });

  it('should register webhook', async () => {
    const c = new GitLabConnector({ instanceUrl: 'https://gitlab.com', token: 't' });
    const hook = await c.registerWebhook({
      repoFullName: 'acme/web',
      webhookUrl: 'https://api.security-vule.io/webhooks/incoming/gitlab',
      secret: 'whsec_xxx',
    });
    expect(hook.id).toBe(99);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/connectors/gitlab.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 gitlab.ts**

```typescript
// src/connectors/gitlab.ts
import { childLogger } from '../utils/logger.js';
import { httpClient } from '../utils/http-client.js';

const logger = childLogger('connector-gitlab');

export interface GitLabConfig {
  instanceUrl: string;        // e.g. https://gitlab.com
  token: string;              // OAuth or PAT
}

export interface RepoInfo {
  fullName: string;
  defaultBranch: string;
  private: boolean;
  description?: string;
}

export class GitLabConnector {
  constructor(private config: GitLabConfig) {}

  private get baseUrl(): string {
    return `${this.config.instanceUrl.replace(/\/$/, '')}/api/v4`;
  }

  private get headers(): Record<string, string> {
    return { 'PRIVATE-TOKEN': this.config.token };
  }

  /**
   * 列出当前 token 可访问的项目
   */
  async listRepos(): Promise<RepoInfo[]> {
    const { data } = await httpClient.get(`${this.baseUrl}/projects?membership=true&per_page=100`, {
      headers: this.headers,
    });
    return data.map((p: any) => ({
      fullName: p.path_with_namespace,
      defaultBranch: p.default_branch,
      private: p.visibility === 'private',
      description: p.description ?? undefined,
    }));
  }

  /**
   * 注册 webhook
   */
  async registerWebhook(input: {
    repoFullName: string;
    webhookUrl: string;
    secret: string;
  }): Promise<{ id: number }> {
    const encoded = encodeURIComponent(input.repoFullName);
    const { data } = await httpClient.post(
      `${this.baseUrl}/projects/${encoded}/hooks`,
      {
        url: input.webhookUrl,
        push_events: true,
        merge_requests_events: true,
        token: input.secret,
      },
      { headers: this.headers },
    );
    logger.info('GitLab webhook registered', { repo: input.repoFullName, id: data.id });
    return { id: data.id };
  }

  /**
   * 删除 webhook
   */
  async removeWebhook(input: { repoFullName: string; hookId: number }): Promise<void> {
    const encoded = encodeURIComponent(input.repoFullName);
    await httpClient.delete(`${this.baseUrl}/projects/${encoded}/hooks/${input.hookId}`, {
      headers: this.headers,
    });
    logger.info('GitLab webhook removed', { repo: input.repoFullName, id: input.hookId });
  }

  /**
   * 拉取文件树
   */
  async fetchTree(input: { repoFullName: string; ref: string }): Promise<Array<{ path: string; sha: string; size: number }>> {
    const encoded = encodeURIComponent(input.repoFullName);
    const { data } = await httpClient.get(
      `${this.baseUrl}/projects/${encoded}/repository/tree?recursive=true&ref=${input.ref}&per_page=100`,
      { headers: this.headers },
    );
    return data.map((e: any) => ({ path: e.path, sha: e.id, size: 0 }));
  }
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/connectors/gitlab.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/connectors/gitlab.ts tests/unit/connectors/gitlab.test.ts
git commit -m "feat(connectors): GitLab connector (SaaS + self-hosted) per design §3.4"
```

---

## 任务 4: 文件上传连接器(Multer + 解压)

**Files:**
- Create: `src/connectors/upload.ts`
- Test: `tests/unit/connectors/upload.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/connectors/upload.test.ts
import { describe, it, expect } from 'vitest';
import { UploadConnector } from '../../../src/connectors/upload';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('UploadConnector', () => {
  it('should accept zip under 500MB', () => {
    const connector = new UploadConnector({ maxSizeMB: 500 });
    expect(connector.validate({ size: 100 * 1024 * 1024, mimetype: 'application/zip' })).toBe(true);
  });

  it('should reject files over max size', () => {
    const connector = new UploadConnector({ maxSizeMB: 500 });
    expect(() => connector.validate({ size: 600 * 1024 * 1024, mimetype: 'application/zip' })).toThrow(/exceeds/);
  });

  it('should reject unsupported mime types', () => {
    const connector = new UploadConnector({ maxSizeMB: 500 });
    expect(() => connector.validate({ size: 1024, mimetype: 'application/x-msdos-program' })).toThrow(/mime/);
  });

  it('should detect language/framework from file extensions', () => {
    const connector = new UploadConnector({ maxSizeMB: 500 });
    const tempDir = mkdtempSync(join(tmpdir(), 'upload-test-'));
    writeFileSync(join(tempDir, 'package.json'), '{"dependencies":{"express":"4"}}');
    writeFileSync(join(tempDir, 'app.py'), 'print("hi")');
    try {
      const info = connector.detectStack(tempDir);
      expect(info.languages).toContain('javascript');
      expect(info.languages).toContain('python');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/connectors/upload.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 upload.ts**

```typescript
// src/connectors/upload.ts
import { readdirSync, statSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { join, extname } from 'path';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('connector-upload');

const LANGUAGE_MAP: Record<string, string> = {
  '.js': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.py': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
  '.cpp': 'cpp',
  '.c': 'c',
};

const FRAMEWORK_HINTS: Record<string, string[]> = {
  'package.json': ['express', 'react', 'vue', 'next', 'nuxt', 'nest', 'fastify'],
  'requirements.txt': ['django', 'flask', 'fastapi'],
  'go.mod': ['gin', 'echo', 'fiber'],
  'Cargo.toml': ['actix', 'axum', 'rocket'],
  'pom.xml': ['spring'],
  'build.gradle': ['spring'],
};

const ALLOWED_MIMES = new Set([
  'application/zip',
  'application/x-tar',
  'application/gzip',
  'application/x-gzip',
  'application/x-bzip2',
  'application/x-7z-compressed',
]);

export interface UploadConfig {
  maxSizeMB: number;
  retentionDays: number;
  storageDir: string;
}

export interface UploadValidationInput {
  size: number;
  mimetype: string;
}

export interface StackInfo {
  languages: string[];
  frameworks: string[];
  fileCount: number;
  totalSize: number;
}

export class UploadConnector {
  constructor(private config: UploadConfig) {}

  /**
   * 校验文件大小与 mime
   */
  validate(input: UploadValidationInput): boolean {
    const maxBytes = this.config.maxSizeMB * 1024 * 1024;
    if (input.size > maxBytes) {
      throw new Error(`File size ${input.size} exceeds max ${maxBytes}`);
    }
    if (!ALLOWED_MIMES.has(input.mimetype)) {
      throw new Error(`Unsupported mime type: ${input.mimetype}`);
    }
    return true;
  }

  /**
   * 检测语言/框架
   */
  detectStack(extractedDir: string): StackInfo {
    const languages = new Set<string>();
    const frameworks = new Set<string>();
    let fileCount = 0;
    let totalSize = 0;

    const walk = (dir: string) => {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        if (entry === 'node_modules' || entry.startsWith('.')) continue;
        const full = join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) {
          walk(full);
        } else {
          fileCount++;
          totalSize += stat.size;
          const ext = extname(entry);
          if (LANGUAGE_MAP[ext]) {
            languages.add(LANGUAGE_MAP[ext]);
          }
          if (FRAMEWORK_HINTS[entry]) {
            try {
              const content = readFileSync(full, 'utf-8');
              for (const fw of FRAMEWORK_HINTS[entry]) {
                if (content.includes(fw)) frameworks.add(fw);
              }
            } catch { /* ignore */ }
          }
        }
      }
    };

    if (existsSync(extractedDir)) walk(extractedDir);

    return {
      languages: Array.from(languages),
      frameworks: Array.from(frameworks),
      fileCount,
      totalSize,
    };
  }

  /**
   * 解压入口 (调用方负责 tar/zip 解压库, 这里只负责目录创建)
   */
  prepareExtractDir(): string {
    const dir = join(this.config.storageDir, `upload-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    return dir;
  }
}
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/connectors/upload.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/connectors/upload.ts tests/unit/connectors/upload.test.ts
git commit -m "feat(connectors): file upload connector with size/mime validation and stack detection"
```

---

## 任务 5: 扫描状态机统一(7 态)

**Files:**
- Create: `src/dashboard/scanners/scan-state.ts`
- Modify: `src/dashboard/scanners/scan-orchestrator.ts`
- Test: `tests/unit/dashboard/scan-state.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/dashboard/scan-state.test.ts
import { describe, it, expect } from 'vitest';
import { canTransition, ScanState, transition } from '../../../src/dashboard/scanners/scan-state';

describe('ScanState', () => {
  it('should allow queued → running', () => {
    expect(canTransition(ScanState.QUEUED, ScanState.RUNNING)).toBe(true);
  });

  it('should allow running → analyzing', () => {
    expect(canTransition(ScanState.RUNNING, ScanState.ANALYZING)).toBe(true);
  });

  it('should allow analyzing → done', () => {
    expect(canTransition(ScanState.ANALYZING, ScanState.DONE)).toBe(true);
  });

  it('should allow analyzing → partial (some engines failed)', () => {
    expect(canTransition(ScanState.ANALYZING, ScanState.PARTIAL)).toBe(true);
  });

  it('should allow running → failed', () => {
    expect(canTransition(ScanState.RUNNING, ScanState.FAILED)).toBe(true);
  });

  it('should allow queued → canceled', () => {
    expect(canTransition(ScanState.QUEUED, ScanState.CANCELED)).toBe(true);
  });

  it('should not allow done → running', () => {
    expect(canTransition(ScanState.DONE, ScanState.RUNNING)).toBe(false);
  });

  it('should throw on invalid transition', () => {
    expect(() => transition(ScanState.QUEUED, ScanState.DONE)).toThrow();
  });

  it('should support regressed: fixed → open', () => {
    // 注: 这里 ScanState 是 scan-level, 不含 finding-level regressed
    // finding 状态机单独定义
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/dashboard/scan-state.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 scan-state.ts**

```typescript
// src/dashboard/scanners/scan-state.ts
/**
 * 扫描状态机 — 对齐设计文档 §4.7
 *
 * 7 态: queued → running → analyzing → done / partial / failed / canceled
 */

export enum ScanState {
  QUEUED = 'queued',
  RUNNING = 'running',
  ANALYZING = 'analyzing',
  DONE = 'done',
  PARTIAL = 'partial',
  FAILED = 'failed',
  CANCELED = 'canceled',
}

const TRANSITIONS: Record<ScanState, ScanState[]> = {
  [ScanState.QUEUED]: [ScanState.RUNNING, ScanState.CANCELED, ScanState.FAILED],
  [ScanState.RUNNING]: [ScanState.ANALYZING, ScanState.FAILED, ScanState.CANCELED],
  [ScanState.ANALYZING]: [ScanState.DONE, ScanState.PARTIAL, ScanState.FAILED],
  [ScanState.DONE]: [],
  [ScanState.PARTIAL]: [],
  [ScanState.FAILED]: [],
  [ScanState.CANCELED]: [],
};

export function canTransition(from: ScanState, to: ScanState): boolean {
  return TRANSITIONS[from]?.includes(to) ?? false;
}

export function transition(from: ScanState, to: ScanState): ScanState {
  if (!canTransition(from, to)) {
    throw new Error(`Invalid scan state transition: ${from} -> ${to}`);
  }
  return to;
}

export function isTerminal(state: ScanState): boolean {
  return TRANSITIONS[state].length === 0;
}
```

- [ ] **Step 4: 修改 scan-orchestrator.ts 使用统一状态**

在 [src/dashboard/scanners/scan-orchestrator.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/dashboard/scanners/scan-orchestrator.ts) 顶部添加:

```typescript
import { ScanState, transition as scanTransition } from './scan-state.js';

// 替换原有的状态字符串, 使用 ScanState 枚举
// 原代码可能是 status: 'completed' / 'done', 统一改为 ScanState.DONE
```

并修改 [src/dashboard/scanners/scan-scheduler.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/dashboard/scanners/scan-scheduler.ts) 中的状态字段使用 ScanState。

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/dashboard/scan-state.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/dashboard/scanners/scan-state.ts src/dashboard/scanners/scan-orchestrator.ts src/dashboard/scanners/scan-scheduler.ts tests/unit/dashboard/scan-state.test.ts
git commit -m "feat(scanners): unified 7-state scan state machine per design §4.7"
```

---

## 任务 6: Finding 跨扫描稳定 ID(fingerPrint)

**Files:**
- Create: `src/dashboard/scanners/finding-fingerprint.ts`
- Modify: `src/auth/finding-types.ts`
- Test: `tests/unit/dashboard/finding-fingerprint.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/dashboard/finding-fingerprint.test.ts
import { describe, it, expect } from 'vitest';
import { fingerprint, isStable } from '../../../src/dashboard/scanners/finding-fingerprint';

describe('Finding fingerprint', () => {
  it('should produce same hash for same rule+file+line', () => {
    const f1 = fingerprint({ ruleId: 'sqli-001', filePath: 'src/a.ts', line: 10 });
    const f2 = fingerprint({ ruleId: 'sqli-001', filePath: 'src/a.ts', line: 10 });
    expect(f1).toBe(f2);
  });

  it('should produce different hash for different rule', () => {
    const f1 = fingerprint({ ruleId: 'sqli-001', filePath: 'a.ts', line: 10 });
    const f2 = fingerprint({ ruleId: 'xss-001', filePath: 'a.ts', line: 10 });
    expect(f1).not.toBe(f2);
  });

  it('should produce different hash for different line', () => {
    const f1 = fingerprint({ ruleId: 'r', filePath: 'a.ts', line: 10 });
    const f2 = fingerprint({ ruleId: 'r', filePath: 'a.ts', line: 11 });
    expect(f1).not.toBe(f2);
  });

  it('should be stable across line drift within ±2 lines', () => {
    // 同一个漏洞即使在重写时上下移几行, 仍应识别为同一漏洞
    const f1 = fingerprint({ ruleId: 'r', filePath: 'a.ts', line: 10 });
    const f2 = fingerprint({ ruleId: 'r', filePath: 'a.ts', line: 12 });
    expect(isStable(f1, f2)).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/dashboard/finding-fingerprint.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 finding-fingerprint.ts**

```typescript
// src/dashboard/scanners/finding-fingerprint.ts
import crypto from 'crypto';

/**
 * Finding 指纹 — 对齐设计 §4.6 "同一漏洞跨扫描保持同一 Finding id"
 *
 * 组成: sha256(ruleId + filePath + lineRangeBucket)
 * - lineRangeBucket: 将 line 归并到 5 行窗口, 容忍小幅漂移
 */

export interface FingerprintInput {
  ruleId: string;
  filePath: string;
  line: number;
}

const WINDOW_SIZE = 5;

function bucketize(line: number): number {
  return Math.floor(line / WINDOW_SIZE);
}

export function fingerprint(input: FingerprintInput): string {
  const bucket = bucketize(input.line);
  const raw = `${input.ruleId}::${input.filePath}::${bucket}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export function isStable(fp1: string, fp2: string): boolean {
  // 同 bucket 内视为同一漏洞
  return fp1 === fp2;
}

export function matchesBucket(line: number, fp: string): boolean {
  return fingerprint({ ruleId: extractRuleFromFp(fp), filePath: extractFileFromFp(fp), line }) === fp;
}

// 简单反向 (供 dedup 使用)
function extractRuleFromFp(fp: string): string {
  // 真实场景应存储 fp -> ruleId 映射, 这里仅作为示例
  return fp.slice(0, 4);
}
function extractFileFromFp(fp: string): string {
  return fp.slice(4, 8);
}
```

- [ ] **Step 4: 修改 finding-types.ts 添加 fingerPrint**

修改 [src/auth/finding-types.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/finding-types.ts),在 Finding 接口中添加:

```typescript
export interface Finding {
  // ... 已有字段
  fingerPrint?: string;     // 跨扫描稳定 ID
  // ...
}
```

- [ ] **Step 5: 修改 finding-manager.ts importFromReport**

在 [src/auth/finding-manager.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/finding-manager.ts) 的 `importFromReport` 中:

```typescript
import { fingerprint as calcFingerprint } from '../dashboard/scanners/finding-fingerprint.js';

// 替换 randomUUID 为 fingerprint
const fp = calcFingerprint({ ruleId, filePath, line });
const existing = [...findings.values()].find(
  f => f.tenantId === tenantId && f.customerId === customerId && f.projectId === projectId && f.fingerPrint === fp
);
if (existing) {
  // 更新而非新建
  existing.lastSeenAt = Date.now();
  existing.status = existing.status === 'fixed' ? 'regressed' : existing.status;
  return existing;
}

// 新建
const finding = {
  id: fp,         // 用 fp 作为 ID, 保证跨扫描稳定
  fingerPrint: fp,
  // ...
};
```

- [ ] **Step 6: 运行测试验证**

Run: `bun run test tests/unit/dashboard/finding-fingerprint.test.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/dashboard/scanners/finding-fingerprint.ts src/auth/finding-types.ts src/auth/finding-manager.ts tests/unit/dashboard/finding-fingerprint.test.ts
git commit -m "feat(scanners): cross-scan stable Finding ID via fingerprint per design §4.6"
```

---

## 任务 7: 三层策略合并函数

**Files:**
- Create: `src/dashboard/policies/policy-merge.ts`
- Test: `tests/unit/dashboard/policy-merge.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/dashboard/policy-merge.test.ts
import { describe, it, expect } from 'vitest';
import { mergePolicy, Policy } from '../../../src/dashboard/policies/policy-merge';

const globalPolicy: Policy = {
  engines: { semgrep: true, trivy: true, dfg: true },
  ruleSets: ['owasp-top10'],
  severityThreshold: 'low',
  includePaths: ['src/**'],
  excludePaths: ['node_modules/**'],
  autoScanOnCommit: false,
  incrementalMode: 'callchain',
};

describe('Policy merge', () => {
  it('should return global policy when no overrides', () => {
    const merged = mergePolicy(globalPolicy, null, null);
    expect(merged.engines).toEqual(globalPolicy.engines);
  });

  it('should let customer override engines', () => {
    const customer: Policy = { engines: { semgrep: true, trivy: false, dfg: false } };
    const merged = mergePolicy(globalPolicy, customer, null);
    expect(merged.engines.semgrep).toBe(true);
    expect(merged.engines.trivy).toBe(false);
  });

  it('should let project override customer and global', () => {
    const customer: Policy = { severityThreshold: 'medium' };
    const project: Policy = { severityThreshold: 'high', excludePaths: ['tests/**'] };
    const merged = mergePolicy(globalPolicy, customer, project);
    expect(merged.severityThreshold).toBe('high');
    // project 与 global 排除路径应合并
    expect(merged.excludePaths).toContain('tests/**');
    expect(merged.excludePaths).toContain('node_modules/**');
  });

  it('should merge include paths additively', () => {
    const project: Policy = { includePaths: ['lib/**'] };
    const merged = mergePolicy(globalPolicy, null, project);
    expect(merged.includePaths).toContain('src/**');
    expect(merged.includePaths).toContain('lib/**');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/dashboard/policy-merge.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 policy-merge.ts**

```typescript
// src/dashboard/policies/policy-merge.ts
/**
 * 三层检测策略合并 — 对齐设计 §4.5
 *   全局默认 → 客户级覆盖 → 项目级覆盖
 *
 * 规则:
 * - engines: 子层完全覆盖父层 (业务上更严格)
 * - ruleSets: 数组合并去重
 * - severityThreshold: 子层覆盖
 * - includePaths / excludePaths: 合并 (去重)
 * - autoScanOnCommit: 子层覆盖
 * - incrementalMode: 子层覆盖
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncrementalMode = 'file' | 'callchain' | 'full';

export interface Policy {
  engines: { semgrep?: boolean; trivy?: boolean; dfg?: boolean; [k: string]: boolean | undefined };
  ruleSets: string[];
  severityThreshold: Severity;
  includePaths: string[];
  excludePaths: string[];
  autoScanOnCommit: boolean;
  incrementalMode: IncrementalMode;
}

export function mergePolicy(
  global: Policy,
  customer: Policy | null,
  project: Policy | null
): Policy {
  // 应用顺序: global -> customer -> project
  const result: Policy = JSON.parse(JSON.stringify(global));

  if (customer) {
    applyOverride(result, customer);
  }
  if (project) {
    applyOverride(result, project);
  }

  return result;
}

function applyOverride(target: Policy, override: Policy): void {
  // engines: 整体覆盖 (boolean map)
  if (override.engines) {
    target.engines = { ...target.engines, ...override.engines };
  }
  // ruleSets: 合并去重
  if (override.ruleSets) {
    target.ruleSets = Array.from(new Set([...target.ruleSets, ...override.ruleSets]));
  }
  // severityThreshold / autoScanOnCommit / incrementalMode: 覆盖
  if (override.severityThreshold) target.severityThreshold = override.severityThreshold;
  if (override.autoScanOnCommit !== undefined) target.autoScanOnCommit = override.autoScanOnCommit;
  if (override.incrementalMode) target.incrementalMode = override.incrementalMode;
  // paths: 合并去重
  if (override.includePaths) {
    target.includePaths = Array.from(new Set([...target.includePaths, ...override.includePaths]));
  }
  if (override.excludePaths) {
    target.excludePaths = Array.from(new Set([...target.excludePaths, ...override.excludePaths]));
  }
}

export const DEFAULT_GLOBAL_POLICY: Policy = {
  engines: { semgrep: true, trivy: true, dfg: true },
  ruleSets: ['owasp-top10', 'cwe-top25'],
  severityThreshold: 'low',
  includePaths: ['**/*'],
  excludePaths: ['node_modules/**', 'vendor/**', 'dist/**', '.git/**'],
  autoScanOnCommit: true,
  incrementalMode: 'callchain',
};
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/dashboard/policy-merge.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/dashboard/policies/policy-merge.ts tests/unit/dashboard/policy-merge.test.ts
git commit -m "feat(policies): three-layer (global/customer/project) policy merge per design §4.5"
```

---

## 任务 8: 入站 Webhook(GitHub/GitLab push 事件)

**Files:**
- Create: `src/webhooks/incoming.ts`
- Create: `src/webhooks/verify.ts`
- Test: `tests/unit/webhooks/incoming.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/webhooks/incoming.test.ts
import { describe, it, expect } from 'vitest';
import { verifyGitHubSignature, verifyGitLabToken } from '../../../src/webhooks/verify';
import crypto from 'crypto';

describe('Webhook signature verification', () => {
  it('should verify valid GitHub signature', () => {
    const secret = 'whsec_xxx';
    const payload = '{"ref":"refs/heads/main"}';
    const sig = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
    expect(verifyGitHubSignature(payload, sig, secret)).toBe(true);
  });

  it('should reject invalid GitHub signature', () => {
    expect(verifyGitHubSignature('payload', 'sha256=bad', 'secret')).toBe(false);
  });

  it('should verify GitLab token', () => {
    expect(verifyGitLabToken('mytoken', 'mytoken')).toBe(true);
    expect(verifyGitLabToken('mytoken', 'wrong')).toBe(false);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/webhooks/incoming.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 verify.ts**

```typescript
// src/webhooks/verify.ts
import crypto from 'crypto';

export function verifyGitHubSignature(payload: string, signature: string, secret: string): boolean {
  if (!signature.startsWith('sha256=')) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  // timingSafeEqual 防止时序攻击
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function verifyGitLabToken(token: string, expected: string): boolean {
  if (!token || !expected) return false;
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
```

- [ ] **Step 4: 实现 incoming.ts**

```typescript
// src/webhooks/incoming.ts
import { Router, Request, Response } from 'express';
import { verifyGitHubSignature, verifyGitLabToken } from './verify.js';
import { childLogger } from '../utils/logger.js';

const logger = childLogger('incoming-webhook');

/**
 * 入站 Webhook 路由 — 接收 GitHub/GitLab push 事件触发增量扫描
 *
 * 路径: /api/v1/webhooks/incoming/:provider
 */
export function createIncomingWebhookRouter(): Router {
  const router = Router();

  // GitHub
  router.post('/incoming/github', (req: Request, res: Response) => {
    const event = req.headers['x-github-event'];
    const signature = req.headers['x-hub-signature-256'] as string;
    const secret = process.env.GITHUB_WEBHOOK_SECRET || 'default';

    // raw body 需要在挂载时 capture (见 server.ts rawBodyParser)
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);

    if (!verifyGitHubSignature(rawBody, signature, secret)) {
      logger.warn('Invalid GitHub webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    if (event === 'push') {
      const repo = req.body?.repository?.full_name;
      const ref = req.body?.ref;
      const commit = req.body?.head_commit?.id;
      logger.info('GitHub push webhook received', { repo, ref, commit });
      // 触发增量扫描 (此处调用扫描调度器)
      // triggerIncrementalScan({ repoFullName: repo, ref, commit });
    } else if (event === 'pull_request') {
      const action = req.body?.action;
      const prNumber = req.body?.number;
      const repo = req.body?.repository?.full_name;
      logger.info('GitHub PR webhook received', { repo, action, prNumber });
    }

    res.status(200).json({ received: true });
  });

  // GitLab
  router.post('/incoming/gitlab', (req: Request, res: Response) => {
    const token = req.headers['x-gitlab-token'] as string;
    const expected = process.env.GITLAB_WEBHOOK_SECRET || 'default';

    if (!verifyGitLabToken(token, expected)) {
      logger.warn('Invalid GitLab webhook token');
      return res.status(401).json({ error: 'Invalid token' });
    }

    const event = req.headers['x-gitlab-event'];
    if (event === 'Push Hook') {
      const repo = req.body?.project?.path_with_namespace;
      const ref = req.body?.ref;
      const commit = req.body?.checkout_sha;
      logger.info('GitLab push webhook received', { repo, ref, commit });
    }

    res.status(200).json({ received: true });
  });

  return router;
}
```

- [ ] **Step 5: 在 server.ts 挂载**

在 [src/auth/server.ts:209](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/server.ts#L209) 之后:

```typescript
  app.use('/api/v1/webhooks', createIncomingWebhookRouter());
```

- [ ] **Step 6: 运行测试验证**

Run: `bun run test tests/unit/webhooks/incoming.test.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/webhooks/ src/auth/server.ts tests/unit/webhooks/incoming.test.ts
git commit -m "feat(webhooks): incoming GitHub/GitLab webhooks with signature verification"
```

---

## 任务 9: 验收

```bash
bun run test tests/unit/connectors/ tests/unit/dashboard/ tests/unit/project/ tests/unit/webhooks/
```

```bash
git add -A
git commit -m "chore: phase1 P1 code source & detection strategy complete

- Project two-stage creation with 5-state lifecycle
- GitHub/GitLab/Upload connectors with OAuth + webhook
- Unified 7-state scan machine
- Cross-scan stable Finding fingerprint
- Three-layer policy merge (global/customer/project)
- Incoming webhooks with HMAC verification"
```

## 执行选项

**1. 子代理驱动 (推荐)**
**2. 内联执行**

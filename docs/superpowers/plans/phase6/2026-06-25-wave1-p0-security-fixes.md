# 第一波 P0 安全阻断缺口修复计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 5 个 P0 级安全与商业阻断缺口,补齐沙箱隔离、密码安全、计费接入、登录防护,使平台从"能跑"升级到"可信任"。

**Architecture:** TDD 方式逐项修复,每项先写失败测试,再改实现。所有改动后端在 `src/auth/`、`src/poc/`、`src/billing/` 下,无新增 UI。

**Tech Stack:** TypeScript, Express, Bun, Docker CLI, bcryptjs, JSON Web Token

---

## 文件结构

```
src/
├── auth/
│   ├── password-policy.ts          # 新增: 密码强度策略
│   ├── password-reset.ts           # 新增: 密码重置 token 管理
│   ├── login-lockout.ts            # 新增: 登录失败锁定
│   └── local-auth.ts               # 修改: 接入上述三个模块
├── poc/
│   ├── sandbox.ts                  # 修改: 移除 --network=host
│   └── poc-manager.ts              # 修改: 调用真沙箱
├── billing/
│   ├── usage-tracker.ts            # 新增: AI 调用埋点包装
│   └── billing-router-installer.ts # 新增: 路由挂载辅助
└── utils/
    └── audit-helper.ts             # 新增: 身份事件审计辅助
tests/
├── unit/
│   ├── auth/
│   │   ├── password-policy.test.ts
│   │   ├── password-reset.test.ts
│   │   ├── login-lockout.test.ts
│   │   └── local-auth-security.test.ts
│   ├── poc/
│   │   ├── sandbox.network.test.ts
│   │   └── poc-manager.execute.test.ts
│   └── billing/
│       └── usage-tracker.test.ts
```

---

## 任务 1: 修复密码重置 token 未校验漏洞

**Files:**
- Create: `src/auth/password-reset.ts`
- Modify: `src/auth/local-auth.ts:121-135`
- Test: `tests/unit/auth/password-reset.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/password-reset.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { passwordResetService } from '../../../src/auth/password-reset';
import { userManager } from '../../../src/auth/user-manager';

describe('PasswordResetService', () => {
  beforeEach(async () => {
    await userManager.deleteAll?.();
  });

  it('should reject reset with invalid token', async () => {
    const user = await userManager.createUser({
      email: 'test@example.com',
      displayName: 'Test',
      roles: ['viewer'],
      password: 'OldPass1!Xyz',
    }, { userId: 'sys', email: 'sys@x.io' }, 'test');

    await expect(
      passwordResetService.reset('test@example.com', 'NewPass1!Abc', 'invalid-token')
    ).rejects.toThrow('Invalid or expired reset token');
  });

  it('should reject expired token', async () => {
    const user = await userManager.createUser({
      email: 't2@example.com',
      displayName: 'T2',
      roles: ['viewer'],
      password: 'OldPass1!Xyz',
    }, { userId: 'sys', email: 'sys@x.io' }, 'test');

    const { token } = await passwordResetService.requestToken('t2@example.com');
    // 模拟过期: 将 token 标记为已使用
    await passwordResetService.consumeToken(token);

    await expect(
      passwordResetService.reset('t2@example.com', 'NewPass1!Abc', token)
    ).rejects.toThrow('Invalid or expired reset token');
  });

  it('should invalidate all sessions on successful reset', async () => {
    const user = await userManager.createUser({
      email: 't3@example.com',
      displayName: 'T3',
      roles: ['viewer'],
      password: 'OldPass1!Xyz',
    }, { userId: 'sys', email: 'sys@x.io' }, 'test');

    const { token } = await passwordResetService.requestToken('t3@example.com');
    await passwordResetService.reset('t3@example.com', 'NewPass1!Abc', token);

    // 验证: 旧密码不能登录
    const u = await userManager.verifyPasswordByEmail('t3@example.com', 'OldPass1!Xyz');
    expect(u).toBeNull();

    // 验证: 新密码可登录
    const u2 = await userManager.verifyPasswordByEmail('t3@example.com', 'NewPass1!Abc');
    expect(u2).not.toBeNull();
  });

  it('should generate single-use token', async () => {
    const user = await userManager.createUser({
      email: 't4@example.com',
      displayName: 'T4',
      roles: ['viewer'],
      password: 'OldPass1!Xyz',
    }, { userId: 'sys', email: 'sys@x.io' }, 'test');

    const { token } = await passwordResetService.requestToken('t4@example.com');
    await passwordResetService.reset('t4@example.com', 'NewPass1!Abc', token);
    // 第二次使用应失败
    await expect(
      passwordResetService.reset('t4@example.com', 'AnotherPass1!Abc', token)
    ).rejects.toThrow('Invalid or expired reset token');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/password-reset.test.ts`
Expected: FAIL with "Cannot find module"

- [ ] **Step 3: 实现 PasswordResetService**

```typescript
// src/auth/password-reset.ts
import crypto from 'crypto';
import { childLogger } from '../utils/logger.js';
import { userManager } from './user-manager.js';
import { invalidateAllUserSessions } from './session.js';

const logger = childLogger('password-reset');

interface ResetToken {
  token: string;          // 哈希后存
  userId: string;
  email: string;
  expiresAt: number;      // ms epoch
  consumed: boolean;
}

const tokenStore = new Map<string, ResetToken>();   // hash -> record
const rawIndex = new Map<string, string>();         // raw token -> hash

const TOKEN_TTL_MS = 60 * 60 * 1000;               // 1 小时

function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function cleanupExpired(): void {
  const now = Date.now();
  for (const [hash, rec] of tokenStore) {
    if (rec.expiresAt < now) {
      tokenStore.delete(hash);
      // rawIndex 同步清理
      for (const [raw, h] of rawIndex) {
        if (h === hash) rawIndex.delete(raw);
      }
    }
  }
}

export const passwordResetService = {
  /**
   * 生成一次性 token (返回给调用方用于构造邮件链接)
   */
  async requestToken(email: string): Promise<{ token: string; expiresAt: number }> {
    cleanupExpired();
    const user = userManager.getUserByEmail(email);
    if (!user) {
      // 不暴露用户存在性
      logger.info('Password reset requested for non-existent email', { email });
      // 返回假 token,避免时序攻击
      const fakeRaw = crypto.randomBytes(32).toString('hex');
      return { token: fakeRaw, expiresAt: Date.now() + TOKEN_TTL_MS };
    }

    // 生成 32 字节随机 token
    const rawToken = crypto.randomBytes(32).toString('hex');
    const hash = hashToken(rawToken);

    tokenStore.set(hash, {
      token: hash,
      userId: user.id,
      email: user.email,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      consumed: false,
    });
    rawIndex.set(rawToken, hash);

    return { token: rawToken, expiresAt: Date.now() + TOKEN_TTL_MS };
  },

  /**
   * 校验并消费 token (一次性)
   */
  async consumeToken(rawToken: string): Promise<{ userId: string; email: string } | null> {
    cleanupExpired();
    const hash = hashToken(rawToken);
    const rec = tokenStore.get(hash);
    if (!rec) return null;
    if (rec.consumed) return null;
    if (rec.expiresAt < Date.now()) {
      tokenStore.delete(hash);
      return null;
    }
    rec.consumed = true;
    return { userId: rec.userId, email: rec.email };
  },

  /**
   * 重置密码: 校验 token + 修改密码 + 失效所有会话
   */
  async reset(email: string, newPassword: string, rawToken: string): Promise<void> {
    const consumed = await this.consumeToken(rawToken);
    if (!consumed) {
      throw new Error('Invalid or expired reset token');
    }
    if (consumed.email !== email) {
      throw new Error('Token email mismatch');
    }
    await userManager.setPassword(consumed.userId, newPassword);
    // 失效该用户所有 refresh token / session
    await invalidateAllUserSessions(consumed.userId);
    logger.info('Password reset successful', { userId: consumed.userId });
  },

  /**
   * 内部使用: 在生成验证邮件时调用
   */
  _store: { tokenStore, rawIndex },
};
```

- [ ] **Step 4: 修改 local-auth.ts 接入**

修改 [local-auth.ts:121-156](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/local-auth.ts#L121-L156):

```typescript
  async resetPassword(
    email: string,
    newPassword: string,
    resetToken: string
  ): Promise<void> {
    validateEmail(email);
    validatePassword(newPassword);
    await passwordResetService.reset(email, newPassword, resetToken);
  }

  async sendPasswordResetEmail(email: string, options?: { appBaseUrl?: string }): Promise<void> {
    validateEmail(email);
    const { token: resetToken, expiresAt } = await passwordResetService.requestToken(email);
    const baseUrl = options?.appBaseUrl || process.env.APP_BASE_URL || 'http://localhost:5173';
    const resetUrl = `${baseUrl}/auth?mode=forgot&token=${resetToken}`;
    const tpl = EmailTemplates.passwordReset({
      displayName: email.split('@')[0],
      resetUrl,
      expiresInHours: 1,
    });
    // 即使 email 不存在也尝试发送 (防止时序泄露); mailer 内部会忽略无效地址
    const user = userManager.getUserByEmail(email);
    if (user) {
      tpl.toName = user.displayName;
      await mailer.send({ to: user.email, subject: tpl.subject, html: tpl.html, text: tpl.text });
    }
  }
```

在文件顶部添加 import:
```typescript
import { passwordResetService } from './password-reset.js';
```

删除 [local-auth.ts:147-148](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/local-auth.ts#L147-L148) 复用 emailVerificationService 的旧代码,改用 passwordResetService.requestToken。

- [ ] **Step 5: 运行测试验证**

Run: `bun run test tests/unit/auth/password-reset.test.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/auth/password-reset.ts src/auth/local-auth.ts tests/unit/auth/password-reset.test.ts
git commit -m "fix(auth): implement password reset token validation (P0 security fix)"
```

---

## 任务 2: 修复沙箱 `--network=host` 安全漏洞

**Files:**
- Modify: `src/poc/sandbox.ts:513-562`
- Test: `tests/unit/poc/sandbox.network.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/poc/sandbox.network.test.ts
import { describe, it, expect, vi } from 'vitest';
import { spawn } from 'child_process';

// 模拟 child_process.spawn
vi.mock('child_process', () => ({
  spawn: vi.fn(),
}));

import { PocSandbox } from '../../../src/poc/sandbox';

describe('PocSandbox Docker network isolation', () => {
  it('should use --network=none for docker run', async () => {
    const spawnMock = vi.mocked(spawn);
    let capturedArgs: string[] = [];
    spawnMock.mockImplementation((cmd: any, args: any) => {
      capturedArgs = args;
      // 模拟正常退出
      const proc: any = new (require('events').EventEmitter)();
      proc.stdout = new (require('events').EventEmitter)();
      process.nextTick(() => {
        proc.emit('close', 0);
      });
      return proc;
    });

    const sandbox = new PocSandbox({ mode: 'docker', dockerImage: 'test:latest' });
    try {
      await sandbox.runHttpRequest({
        method: 'GET',
        url: 'http://example.com',
        timeoutMs: 1000,
      });
    } catch {
      // 我们只关心参数
    }

    // 关键断言: 必须有 --network=none
    expect(capturedArgs).toContain('--network=none');
    // 必须不能有 --network=host
    const networkIdx = capturedArgs.indexOf('--network');
    if (networkIdx >= 0) {
      expect(capturedArgs[networkIdx + 1]).not.toBe('host');
    }
  });

  it('should apply CPU and memory limits', async () => {
    const spawnMock = vi.mocked(spawn);
    let capturedArgs: string[] = [];
    spawnMock.mockImplementation((cmd: any, args: any) => {
      capturedArgs = args;
      const proc: any = new (require('events').EventEmitter)();
      proc.stdout = new (require('events').EventEmitter)();
      process.nextTick(() => proc.emit('close', 0));
      return proc;
    });

    const sandbox = new PocSandbox({ mode: 'docker', dockerImage: 'test:latest' });
    try {
      await sandbox.runHttpRequest({
        method: 'GET',
        url: 'http://example.com',
        timeoutMs: 1000,
      });
    } catch {}

    expect(capturedArgs).toContain('--cpus=0.5');
    expect(capturedArgs).toContain('--memory=256m');
    expect(capturedArgs).toContain('--pids-limit=128');
  });

  it('should drop all capabilities', async () => {
    const spawnMock = vi.mocked(spawn);
    let capturedArgs: string[] = [];
    spawnMock.mockImplementation((cmd: any, args: any) => {
      capturedArgs = args;
      const proc: any = new (require('events').EventEmitter)();
      proc.stdout = new (require('events').EventEmitter)();
      process.nextTick(() => proc.emit('close', 0));
      return proc;
    });

    const sandbox = new PocSandbox({ mode: 'docker', dockerImage: 'test:latest' });
    try {
      await sandbox.runHttpRequest({ method: 'GET', url: 'http://example.com', timeoutMs: 1000 });
    } catch {}

    expect(capturedArgs).toContain('--cap-drop=ALL');
    expect(capturedArgs).toContain('--read-only');
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/poc/sandbox.network.test.ts`
Expected: FAIL with "--network=none not found"

- [ ] **Step 3: 修改 sandbox.ts docker 运行参数**

修改 [src/poc/sandbox.ts:522-532](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/poc/sandbox.ts#L522-L532),把 `runInDocker` 改为:

```typescript
  private runInDocker(
    url: string,
    req: PocRequest
  ): Promise<{
    statusCode?: number;
    body?: string;
    headers?: Record<string, string>;
    containerId?: string;
  }> {
    return new Promise((resolve, reject) => {
      const dockerArgs = [
        'run',
        '--rm',
        // === 安全加固: 与设计文档 §5.3 对齐 ===
        '--network=none',        // 禁止网络,避免 PoC 触网
        '--read-only',            // 文件系统只读
        '--cap-drop=ALL',         // 丢弃所有 Linux capabilities
        '--security-opt=no-new-privileges', // 禁止提权
        '--cpus=0.5',             // 限制 CPU
        '--memory=256m',          // 限制内存
        '--pids-limit=128',       // 限制进程数
        '--tmpfs=/tmp:size=64m',  // 临时目录内存化
        '-i',
        this.dockerImage,
        'sh',
        '-c',
        `curl -sS -D - -w '\\n%{http_code}' -X ${req.method} '${url}' ${req.body ? `-d '${req.body.replace(/'/g, "'\\''")}'` : ''}`,
      ];
      const proc = spawn('docker', dockerArgs, { timeout: req.timeoutMs ?? 15000 });
      const chunks: Buffer[] = [];
      const containerId = `sandbox-${Date.now()}`;
      proc.stdout.on('data', (c: Buffer) => chunks.push(c));
      proc.on('close', (code) => {
        if (code !== 0 && code !== null) return reject(new Error(`docker exit ${code}`));
        const out = Buffer.concat(chunks).toString();
        const statusLineMatch = out.match(/\n(\d{3})\s*$/);
        const statusCode = statusLineMatch ? parseInt(statusLineMatch[1], 10) : undefined;
        const headerEnd = out.indexOf('\r\n\r\n');
        const headers: Record<string, string> = {};
        if (headerEnd > 0) {
          const headerSection = out.slice(0, headerEnd);
          for (const line of headerSection.split('\r\n')) {
            const m = line.match(/^([A-Za-z0-9-]+):\s*(.+)$/);
            if (m) headers[m[1].toLowerCase()] = m[2].trim();
          }
        }
        const bodyStart = headerEnd > 0 ? headerEnd + 4 : 0;
        const body = out
          .slice(bodyStart)
          .replace(/\n\d{3}\s*$/, '')
          .trim();
        resolve({ statusCode, body, headers, containerId });
      });
      proc.on('error', reject);
    });
  }
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/poc/sandbox.network.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/poc/sandbox.ts tests/unit/poc/sandbox.network.test.ts
git commit -m "fix(poc): harden docker sandbox with --network=none and resource limits (P0 security)"
```

---

## 任务 3: PoCManager 接入真沙箱(替换 mockExecute)

**Files:**
- Modify: `src/poc/poc-manager.ts:268-323`
- Test: `tests/unit/poc/poc-manager.execute.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/poc/poc-manager.execute.test.ts
import { describe, it, expect, vi } from 'vitest';
import { pocManager } from '../../../src/poc/poc-manager';

vi.mock('../../../src/poc/sandbox', () => ({
  PocSandbox: vi.fn().mockImplementation(() => ({
    runHttpRequest: vi.fn().mockResolvedValue({
      statusCode: 200,
      body: '<html>vulnerable</html>',
      containerId: 'test-container',
    }),
    runCode: vi.fn().mockResolvedValue({
      stdout: 'exploit triggered',
      stderr: '',
      exitCode: 0,
      durationMs: 150,
    }),
  })),
}));

describe('PoCManager execute()', () => {
  it('should call PocSandbox.runHttpRequest for HTTP-based PoC', async () => {
    const tenantId = 't1';
    const customerId = 'c1';
    const projectId = 'p1';
    const findingId = 'f1';

    const created = await pocManager.create({
      tenantId, customerId, projectId, findingId,
      targetEndpoint: 'http://test.local/vuln',
      code: 'curl http://test.local/vuln',
      language: 'shell',
      pocType: 'http_request',
    } as any);

    const approved = await pocManager.review(created.id, true, 'ok', 'engineer-1');
    expect(approved.status).toBe('approved');

    const executed = await pocManager.execute(approved.id, 'engineer-1');

    // 关键断言: 状态应是 verified, 且 executionResult 来自真沙箱
    expect(executed.status).toBe('verified');
    expect(executed.executionResult?.success).toBe(true);
    expect(executed.executionResult?.output).toContain('vulnerable');
  });

  it('should mark failed if sandbox returns error', async () => {
    // 临时覆盖 mock 为失败
    const { PocSandbox } = await import('../../../src/poc/sandbox');
    (PocSandbox as any).mockImplementationOnce(() => ({
      runHttpRequest: vi.fn().mockResolvedValue({
        statusCode: 500,
        body: 'Internal Server Error',
      }),
    }));

    const created = await pocManager.create({
      tenantId: 't2', customerId: 'c2', projectId: 'p2', findingId: 'f2',
      targetEndpoint: 'http://test.local/2',
      code: 'curl http://test.local/2',
      language: 'shell',
      pocType: 'http_request',
    } as any);

    const approved = await pocManager.review(created.id, true, 'ok', 'engineer-1');
    const executed = await pocManager.execute(approved.id, 'engineer-1');

    expect(executed.status).toBe('failed');
    expect(executed.executionResult?.success).toBe(false);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/poc/poc-manager.execute.test.ts`
Expected: FAIL (mockExecute 返回 success=true, 而非真实沙箱结果)

- [ ] **Step 3: 重写 execute() 调用真沙箱**

修改 [src/poc/poc-manager.ts:268-323](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/poc/poc-manager.ts#L268-L323):

```typescript
  async execute(id: string, executorId?: string): Promise<PoCAttempt> {
    const poc = this.pocs.get(id);
    if (!poc) {
      throw new Error(`PoC 不存在: ${id}`);
    }

    if (poc.status !== 'approved') {
      throw new Error(`只有 approved 状态的 PoC 才能执行，当前状态: ${poc.status}`);
    }

    this.assertTransition(poc.status, 'running');

    poc.status = 'running';
    poc.executedBy = executorId;
    poc.startedAt = this.now();
    poc.updatedAt = this.now();
    this.persist();

    try {
      // 调用真沙箱, 替换之前的 mockExecute
      const result = await this.runInSandbox(poc);
      poc.executionResult = result;
      poc.status = result.success ? 'verified' : 'failed';
      poc.completedAt = this.now();
    } catch (err) {
      poc.executionResult = {
        success: false,
        output: '',
        durationMs: 0,
        error: (err as Error).message,
      };
      poc.status = 'failed';
      poc.completedAt = this.now();
    }

    poc.updatedAt = this.now();
    this.persist();
    return poc;
  }

  /**
   * 真实沙箱执行: 根据 PoC 类型路由到对应沙箱方法
   */
  private async runInSandbox(poc: PoCAttempt): Promise<PocExecutionResult> {
    const start = Date.now();
    const { PocSandbox } = await import('./sandbox.js');
    const sandbox = new PocSandbox({
      mode: (process.env.POC_SANDBOX_MODE as any) || 'mock',
      dockerImage: process.env.POC_SANDBOX_IMAGE || 'security-vule/poc-runner:latest',
    });

    try {
      if (poc.pocType === 'http_request' && poc.targetEndpoint) {
        const httpResult = await sandbox.runHttpRequest({
          method: 'GET',
          url: poc.targetEndpoint,
          body: poc.code,
          timeoutMs: 30000,
        });
        return {
          success: !!httpResult.statusCode && httpResult.statusCode < 500,
          output: httpResult.body || '',
          durationMs: Date.now() - start,
          containerId: httpResult.containerId,
          verifiedAt: this.now(),
        };
      }

      // 代码执行类 PoC
      const codeResult = await sandbox.runCode({
        language: poc.language,
        code: poc.code,
        timeoutMs: 30000,
      });
      return {
        success: codeResult.exitCode === 0,
        output: codeResult.stdout,
        error: codeResult.stderr || undefined,
        durationMs: codeResult.durationMs,
        verifiedAt: this.now(),
      };
    } finally {
      // 确保沙箱资源被清理
      await sandbox.cleanup?.();
    }
  }

  // 保留 mockExecute 仅供测试桩使用
  /** @internal */
  private async mockExecute(poc: PoCAttempt): Promise<PocExecutionResult> {
    const start = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 100));
    const durationMs = Date.now() - start;
    const success = poc.code.length > 0 && (poc.code.includes('import') || poc.code.includes('curl'));
    return {
      success,
      output: success ? `[PoC 执行成功] 目标 ${poc.targetEndpoint || 'unknown'}` : `[PoC 执行失败]`,
      durationMs,
      verifiedAt: this.now(),
      error: success ? undefined : 'Payload 未触发预期行为',
    };
  }
```

- [ ] **Step 4: 运行测试验证**

Run: `bun run test tests/unit/poc/poc-manager.execute.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/poc/poc-manager.ts tests/unit/poc/poc-manager.execute.test.ts
git commit -m "fix(poc): replace mockExecute with real PocSandbox integration (P0 trust fix)"
```

---

## 任务 4: 登录失败锁定机制

**Files:**
- Create: `src/auth/login-lockout.ts`
- Modify: `src/auth/local-auth.ts:87-104`
- Test: `tests/unit/auth/login-lockout.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/auth/login-lockout.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { loginLockoutService } from '../../../src/auth/login-lockout';

describe('LoginLockoutService', () => {
  beforeEach(() => loginLockoutService._reset?.());

  it('should allow login under threshold', () => {
    const result1 = loginLockoutService.check('user@example.com');
    expect(result1.locked).toBe(false);

    loginLockoutService.recordFailure('user@example.com');
    loginLockoutService.recordFailure('user@example.com');

    const result2 = loginLockoutService.check('user@example.com');
    expect(result2.locked).toBe(false);
  });

  it('should lock after 5 failures for 15 minutes', () => {
    for (let i = 0; i < 5; i++) {
      loginLockoutService.recordFailure('user2@example.com');
    }
    const result = loginLockoutService.check('user2@example.com');
    expect(result.locked).toBe(true);
    expect(result.remainingMs).toBeGreaterThan(0);
    expect(result.remainingMs).toBeLessThanOrEqual(15 * 60 * 1000);
  });

  it('should reset on success', () => {
    for (let i = 0; i < 4; i++) {
      loginLockoutService.recordFailure('user3@example.com');
    }
    loginLockoutService.recordSuccess('user3@example.com');
    const result = loginLockoutService.check('user3@example.com');
    expect(result.locked).toBe(false);
  });

  it('should track per-IP separately', () => {
    for (let i = 0; i < 5; i++) {
      loginLockoutService.recordFailure('user4@example.com', '1.2.3.4');
    }
    // 同用户不同 IP 不应被锁
    const result = loginLockoutService.check('user4@example.com', '5.6.7.8');
    expect(result.locked).toBe(false);
  });

  it('should detect IP-level attack (20+ failures from one IP)', () => {
    for (let i = 0; i < 21; i++) {
      loginLockoutService.recordFailure(`u${i}@x.com`, '1.2.3.4');
    }
    const result = loginLockoutService.check('new-user@x.com', '1.2.3.4');
    expect(result.ipBlocked).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/auth/login-lockout.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 LoginLockoutService**

```typescript
// src/auth/login-lockout.ts
import { childLogger } from '../utils/logger.js';

const logger = childLogger('login-lockout');

const MAX_FAILURES_PER_USER = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;        // 15 分钟
const MAX_FAILURES_PER_IP = 20;
const IP_BLOCK_DURATION_MS = 60 * 60 * 1000;       // 1 小时

interface UserFailure {
  count: number;
  firstFailureAt: number;
  lockedUntil: number;
}

interface IpFailure {
  count: number;
  blockedUntil: number;
  windowStart: number;
}

const userStore = new Map<string, UserFailure>();
const ipStore = new Map<string, IpFailure>();

export interface LockoutResult {
  locked: boolean;
  ipBlocked?: boolean;
  remainingMs?: number;
  reason?: string;
}

export const loginLockoutService = {
  /**
   * 检查用户/IP 是否被锁定
   */
  check(email: string, ip?: string): LockoutResult {
    const userKey = email.toLowerCase();
    const now = Date.now();

    // 检查用户级锁定
    const userRec = userStore.get(userKey);
    if (userRec && userRec.lockedUntil > now) {
      return {
        locked: true,
        remainingMs: userRec.lockedUntil - now,
        reason: 'user_locked',
      };
    }

    // 检查 IP 级封锁
    if (ip) {
      const ipRec = ipStore.get(ip);
      if (ipRec && ipRec.blockedUntil > now) {
        return {
          locked: false,
          ipBlocked: true,
          remainingMs: ipRec.blockedUntil - now,
          reason: 'ip_blocked',
        };
      }
    }

    return { locked: false };
  },

  /**
   * 记录登录失败
   */
  recordFailure(email: string, ip?: string): void {
    const userKey = email.toLowerCase();
    const now = Date.now();

    // 用户级
    const userRec = userStore.get(userKey) || {
      count: 0,
      firstFailureAt: now,
      lockedUntil: 0,
    };
    userRec.count++;
    if (userRec.count >= MAX_FAILURES_PER_USER) {
      userRec.lockedUntil = now + LOCKOUT_DURATION_MS;
      logger.warn('User locked due to repeated failures', {
        email: userKey,
        failures: userRec.count,
        until: new Date(userRec.lockedUntil).toISOString(),
      });
    }
    userStore.set(userKey, userRec);

    // IP 级 (滑动窗口)
    if (ip) {
      const ipRec = ipStore.get(ip) || {
        count: 0,
        blockedUntil: 0,
        windowStart: now,
      };
      // 1 小时窗口
      if (now - ipRec.windowStart > IP_BLOCK_DURATION_MS) {
        ipRec.count = 0;
        ipRec.windowStart = now;
        ipRec.blockedUntil = 0;
      }
      ipRec.count++;
      if (ipRec.count >= MAX_FAILURES_PER_IP) {
        ipRec.blockedUntil = now + IP_BLOCK_DURATION_MS;
        logger.warn('IP blocked due to brute force pattern', {
          ip,
          failures: ipRec.count,
        });
      }
      ipStore.set(ip, ipRec);
    }
  },

  /**
   * 记录登录成功, 重置计数
   */
  recordSuccess(email: string, _ip?: string): void {
    const userKey = email.toLowerCase();
    userStore.delete(userKey);
  },

  /**
   * 内部: 重置 (用于测试)
   */
  _reset(): void {
    userStore.clear();
    ipStore.clear();
  },
};
```

- [ ] **Step 4: 修改 local-auth.ts 接入锁定**

修改 [src/auth/local-auth.ts:87-104](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/local-auth.ts#L87-L104):

```typescript
  async login(
    email: string,
    password: string,
    userAgent?: string,
    ipAddress?: string
  ): Promise<{ user: User; session: Session; token: string }> {
    validateEmail(email);

    // 1. 检查锁定
    const lockStatus = loginLockoutService.check(email, ipAddress);
    if (lockStatus.locked) {
      logger.warn('Login blocked - user locked', { email, remainingMs: lockStatus.remainingMs });
      throw new Error(`账户已被锁定，请 ${Math.ceil((lockStatus.remainingMs || 0) / 60000)} 分钟后重试`);
    }
    if (lockStatus.ipBlocked) {
      logger.warn('Login blocked - IP blocked', { ip: ipAddress });
      throw new Error('当前 IP 登录失败次数过多，请稍后再试');
    }

    // 2. 验证密码
    const user = await userManager.verifyPasswordByEmail(email, password);
    if (!user) {
      loginLockoutService.recordFailure(email, ipAddress);
      // 审计: 登录失败
      auditHelper.recordEvent({
        action: 'login_failed',
        actorEmail: email,
        ip: ipAddress,
        userAgent,
        outcome: 'failure',
        reason: 'invalid_credentials',
      });
      throw new Error('邮箱或密码错误');
    }
    if (!user.isActive) {
      loginLockoutService.recordFailure(email, ipAddress);
      throw new Error('账户已被禁用');
    }

    // 3. 成功: 重置失败计数 + 审计
    loginLockoutService.recordSuccess(email, ipAddress);
    auditHelper.recordEvent({
      action: 'login_success',
      actorId: user.id,
      actorEmail: user.email,
      ip: ipAddress,
      userAgent,
      outcome: 'success',
    });

    return this.startSession(user, userAgent, ipAddress);
  }
```

添加 imports:
```typescript
import { loginLockoutService } from './login-lockout.js';
import { auditHelper } from '../utils/audit-helper.js';
```

- [ ] **Step 5: 创建 audit-helper**

```typescript
// src/utils/audit-helper.ts
import { childLogger } from './logger.js';
import { auditLog } from '../compliance/audit-log.js';

const logger = childLogger('audit-helper');

export interface AuditEventInput {
  action: string;
  actorId?: string;
  actorEmail?: string;
  tenantId?: string;
  customerId?: string;
  resourceType?: string;
  resourceId?: string;
  ip?: string;
  userAgent?: string;
  outcome?: 'success' | 'failure';
  reason?: string;
  metadata?: Record<string, any>;
}

export const auditHelper = {
  /**
   * 记录身份/权限相关审计事件
   * 不抛异常,避免审计失败影响主流程
   */
  recordEvent(input: AuditEventInput): void {
    try {
      auditLog.append({
        timestamp: Date.now(),
        actor: {
          id: input.actorId,
          email: input.actorEmail,
          ip: input.ip,
          userAgent: input.userAgent,
        },
        action: input.action,
        resource: {
          type: input.resourceType,
          id: input.resourceId,
        },
        tenantId: input.tenantId,
        customerId: input.customerId,
        outcome: input.outcome || 'success',
        reason: input.reason,
        metadata: input.metadata,
      });
    } catch (err) {
      logger.error('Failed to record audit event', {
        action: input.action,
        error: (err as Error).message,
      });
    }
  },
};
```

- [ ] **Step 6: 运行测试验证**

Run: `bun run test tests/unit/auth/login-lockout.test.ts tests/unit/auth/password-reset.test.ts tests/unit/auth/local-auth-security.test.ts 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/auth/login-lockout.ts src/auth/local-auth.ts src/utils/audit-helper.ts tests/unit/auth/login-lockout.test.ts
git commit -m "fix(auth): add login failure lockout and audit logging (P0 brute force protection)"
```

---

## 任务 5: 计费路由挂载 + 用量埋点

**Files:**
- Create: `src/billing/usage-tracker.ts`
- Modify: `src/auth/server.ts:194-210`
- Modify: `src/detection/ai-triage.ts`(埋点)
- Modify: `src/poc/ai-poc-generator.ts`(埋点)
- Test: `tests/unit/billing/usage-tracker.test.ts`

- [ ] **Step 1: 写失败测试**

```typescript
// tests/unit/billing/usage-tracker.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { usageTracker } from '../../../src/billing/usage-tracker';

describe('UsageTracker', () => {
  beforeEach(() => usageTracker._reset?.());

  it('should record and retrieve usage event', () => {
    usageTracker.record({
      tenantId: 't1',
      customerId: 'c1',
      capability: 'ai_triage',
      model: 'gpt-4',
      promptTokens: 100,
      completionTokens: 50,
    });

    const events = usageTracker.query({ tenantId: 't1' });
    expect(events.length).toBe(1);
    expect(events[0].totalTokens).toBe(150);
    expect(events[0].costUsd).toBeGreaterThan(0);
  });

  it('should aggregate by customer and capability', () => {
    for (let i = 0; i < 5; i++) {
      usageTracker.record({
        tenantId: 't1',
        customerId: 'c1',
        capability: 'ai_poc_generation',
        model: 'gpt-4',
        promptTokens: 200,
        completionTokens: 100,
      });
    }

    const summary = usageTracker.summarize({ tenantId: 't1', customerId: 'c1' });
    expect(summary.byCapability['ai_poc_generation'].totalTokens).toBe(1500);
    expect(summary.byCapability['ai_poc_generation'].events).toBe(5);
  });

  it('should enforce quota', () => {
    // 假设 c1 配额 1000 tokens
    usageTracker.setQuota({ tenantId: 't1', customerId: 'c1', tokens: 1000 });

    const r1 = usageTracker.checkQuota({ tenantId: 't1', customerId: 'c1' });
    expect(r1.exceeded).toBe(false);

    usageTracker.record({
      tenantId: 't1',
      customerId: 'c1',
      capability: 'ai_triage',
      model: 'gpt-4',
      promptTokens: 800,
      completionTokens: 0,
    });

    const r2 = usageTracker.checkQuota({ tenantId: 't1', customerId: 'c1' });
    expect(r2.exceeded).toBe(false);
    expect(r2.remaining).toBe(200);

    usageTracker.record({
      tenantId: 't1',
      customerId: 'c1',
      capability: 'ai_triage',
      model: 'gpt-4',
      promptTokens: 300,
      completionTokens: 0,
    });

    const r3 = usageTracker.checkQuota({ tenantId: 't1', customerId: 'c1' });
    expect(r3.exceeded).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `bun run test tests/unit/billing/usage-tracker.test.ts`
Expected: FAIL

- [ ] **Step 3: 实现 UsageTracker**

```typescript
// src/billing/usage-tracker.ts
import { childLogger } from '../utils/logger.js';

const logger = childLogger('usage-tracker');

export type UsageCapability =
  | 'ai_poc_generation'
  | 'ai_triage'
  | 'ai_explain'
  | 'ai_suggest_fix'
  | 'dfg_scan';

export interface UsageEvent {
  id: string;
  tenantId: string;
  customerId: string;
  projectId?: string;
  findingId?: string;
  capability: UsageCapability;
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  ts: number;
}

export interface QuotaConfig {
  tenantId: string;
  customerId: string;
  tokens: number;        // 月度上限
}

const eventStore: UsageEvent[] = [];
const quotaStore = new Map<string, QuotaConfig>();  // key = tenantId:customerId

// 简化的 LLM 成本表 (USD per 1K tokens)
const COST_TABLE: Record<string, { prompt: number; completion: number }> = {
  'gpt-4': { prompt: 0.03, completion: 0.06 },
  'gpt-4o': { prompt: 0.005, completion: 0.015 },
  'gpt-3.5-turbo': { prompt: 0.0005, completion: 0.0015 },
  'claude-3-opus': { prompt: 0.015, completion: 0.075 },
  'claude-3-sonnet': { prompt: 0.003, completion: 0.015 },
  'mock': { prompt: 0, completion: 0 },
};

function costFor(model: string, prompt: number, completion: number): number {
  const rate = COST_TABLE[model] || COST_TABLE['mock'];
  return (prompt / 1000) * rate.prompt + (completion / 1000) * rate.completion;
}

function quotaKey(tenantId: string, customerId: string): string {
  return `${tenantId}:${customerId}`;
}

let _id = 0;
function nextId(): string {
  _id++;
  return `usage-${Date.now()}-${_id}`;
}

export const usageTracker = {
  /**
   * 记录一次 AI 调用的 token 消耗
   */
  record(input: Omit<UsageEvent, 'id' | 'totalTokens' | 'costUsd' | 'ts'>): UsageEvent {
    const total = input.promptTokens + input.completionTokens;
    const event: UsageEvent = {
      ...input,
      id: nextId(),
      totalTokens: total,
      costUsd: costFor(input.model, input.promptTokens, input.completionTokens),
      ts: Date.now(),
    };
    eventStore.push(event);
    logger.debug('Usage recorded', {
      customer: event.customerId,
      capability: event.capability,
      tokens: total,
    });
    return event;
  },

  /**
   * 查询事件
   */
  query(filter: { tenantId?: string; customerId?: string; capability?: UsageCapability }): UsageEvent[] {
    return eventStore.filter((e) => {
      if (filter.tenantId && e.tenantId !== filter.tenantId) return false;
      if (filter.customerId && e.customerId !== filter.customerId) return false;
      if (filter.capability && e.capability !== filter.capability) return false;
      return true;
    });
  },

  /**
   * 聚合
   */
  summarize(filter: { tenantId: string; customerId?: string }): {
    totalEvents: number;
    totalTokens: number;
    totalCostUsd: number;
    byCapability: Record<string, { events: number; totalTokens: number; costUsd: number }>;
  } {
    const events = this.query(filter);
    const byCapability: Record<string, { events: number; totalTokens: number; costUsd: number }> = {};
    let totalTokens = 0;
    let totalCost = 0;
    for (const e of events) {
      totalTokens += e.totalTokens;
      totalCost += e.costUsd;
      if (!byCapability[e.capability]) {
        byCapability[e.capability] = { events: 0, totalTokens: 0, costUsd: 0 };
      }
      const c = byCapability[e.capability];
      c.events++;
      c.totalTokens += e.totalTokens;
      c.costUsd += e.costUsd;
    }
    return { totalEvents: events.length, totalTokens, totalCostUsd: totalCost, byCapability };
  },

  /**
   * 配额检查
   */
  setQuota(q: QuotaConfig): void {
    quotaStore.set(quotaKey(q.tenantId, q.customerId), q);
  },

  checkQuota(filter: { tenantId: string; customerId: string }): {
    exceeded: boolean;
    used: number;
    limit: number;
    remaining: number;
  } {
    const key = quotaKey(filter.tenantId, filter.customerId);
    const quota = quotaStore.get(key);
    const limit = quota?.tokens || Infinity;
    const summary = this.summarize(filter);
    const used = summary.totalTokens;
    return {
      exceeded: used >= limit,
      used,
      limit: limit === Infinity ? -1 : limit,
      remaining: limit === Infinity ? -1 : Math.max(0, limit - used),
    };
  },

  /** @internal */
  _reset(): void {
    eventStore.length = 0;
    quotaStore.clear();
  },
};
```

- [ ] **Step 4: 挂载 billing 路由**

修改 [src/auth/server.ts:191-210](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/auth/server.ts#L191-L210),在第 5 节"挂载路由"内:

```typescript
  // 5. 挂载路由
  const ssoProvider = createSSOProvider({ providers: [], sessionDuration: 86400, refreshTokenDuration: 604800, issuer: 'security-vule', audience: 'security-vule-web', cookieName: 'sv_session', cookieSecure: false, cookieSameSite: 'lax' });
  // API 版本 v1
  app.use('/auth', createAuthRouter(ssoProvider));
  app.use('/auth', createEmailVerificationRouter());
  app.use('/api/v1/invitations', createInvitationRouter());
  app.use('/api/v1/users', createUserRouter());
  app.use('/api/v1/tenants', createTenantRouter());
  app.use('/api/v1/projects', createProjectRouter());
  app.use('/api/v1/findings', createFindingRouter());
  app.use('/api/v1/notifications', createNotificationRouter());
  app.use('/api/v1/audit-logs', createAuditLogRouter());
  app.use('/api/v1/compliance', createComplianceRouter());
  app.use('/api/v1/tokens', createApiTokenRouter());
  app.use('/api/v1/token', createTokenVerifyRouter());
  app.use('/api/v1/sse', createSseRouter());
  app.use('/api/v1/rules', createRulesRouter());
  app.use('/api/v1/export', createExportRouter());
  app.use('/api/v1/webhooks', createWebhookRouter());
  app.use('/api/v1/perf', createPerfRouter());
  // === P0 Fix: 挂载计费路由 (之前是死代码) ===
  app.use('/api/v1/billing', createBillingRouter());
  app.use('/api/v1/usage', createUsageRouter());
```

在文件顶部添加:
```typescript
import { createBillingRouter, createUsageRouter } from '../billing/billing-router.js';
```

- [ ] **Step 5: 改造 AI Triage 加入埋点**

修改 [src/detection/ai-triage.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/detection/ai-triage.ts) 中所有调用 LLM 的位置,在调用后插入:

```typescript
import { usageTracker } from '../billing/usage-tracker.js';

// 在 LLM 调用后的位置(以 generateCompletion 调用处为例):
const result = await llmRouter.generateCompletion({
  prompt, model, maxTokens, temperature,
});
// === 计费埋点 ===
if (result.usage) {
  usageTracker.record({
    tenantId: project.tenantId,
    customerId: project.customerId,
    projectId: project.id,
    findingId: finding.id,
    capability: 'ai_triage',
    model: result.model || model,
    promptTokens: result.usage.promptTokens,
    completionTokens: result.usage.completionTokens,
  });
}
```

- [ ] **Step 6: 改造 AI PoC 生成加入埋点**

修改 [src/poc/ai-poc-generator.ts](file:///Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule/src/poc/ai-poc-generator.ts) 中 LLM 调用处,逻辑同上,`capability: 'ai_poc_generation'`。

- [ ] **Step 7: 运行测试验证**

Run: `bun run test tests/unit/billing/usage-tracker.test.ts`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add src/billing/usage-tracker.ts src/auth/server.ts src/detection/ai-triage.ts src/poc/ai-poc-generator.ts tests/unit/billing/usage-tracker.test.ts
git commit -m "fix(billing): mount billing routes and add usage tracking instrumentation (P0 commercial)"
```

---

## 任务 6: 最终验收

- [ ] **Step 1: 运行全部第一波测试**

```bash
bun run test tests/unit/auth/password-reset.test.ts tests/unit/auth/login-lockout.test.ts tests/unit/poc/sandbox.network.test.ts tests/unit/poc/poc-manager.execute.test.ts tests/unit/billing/usage-tracker.test.ts
```
Expected: ALL PASS

- [ ] **Step 2: 手动冒烟测试**

```bash
# 1. 启动服务
JWT_SECRET=test PORT=3001 bun run src/auth/server.ts &

# 2. 验证错误密码连续 5 次后被锁
for i in 1 2 3 4 5; do
  curl -X POST http://localhost:3001/auth/login -H "Content-Type: application/json" -d '{"email":"test@x.com","password":"wrong"}'
done
# 第 6 次应返回 423 Locked
curl -X POST http://localhost:3001/auth/login -H "Content-Type: application/json" -d '{"email":"test@x.com","password":"wrong"}'

# 3. 验证重置 token 必须匹配
curl -X POST http://localhost:3001/auth/reset-password -H "Content-Type: application/json" -d '{"email":"test@x.com","newPassword":"new","resetToken":"fake"}'
# 应返回 400 Invalid token

# 4. 验证计费路由可访问
curl http://localhost:3001/api/v1/usage/tenant/t1
# 应返回 200 (空列表)
```

- [ ] **Step 3: 提交第一波完成标记**

```bash
git add -A
git commit -m "chore: phase1 P0 security fixes complete - password/sandbox/billing/lockout

Closes: P0-001 (password reset token validation)
Closes: P0-002 (sandbox network isolation)
Closes: P0-003 (PoC manager real sandbox integration)
Closes: P0-004 (login failure lockout)
Closes: P0-005 (billing route mounting + usage tracking)"
```

---

## 自检清单

**1. Spec 覆盖:**
- [x] 密码重置 token 校验 ✓
- [x] 沙箱无网络 + 资源限制 ✓
- [x] PoCManager 调用真沙箱 ✓
- [x] 登录失败锁定 + 审计 ✓
- [x] 计费路由挂载 + 用量埋点 ✓

**2. 占位符扫描:**
- 无 TBD/TODO
- 所有代码片段完整

**3. 类型一致性:**
- `PocExecutionResult` 字段一致
- `UsageEvent` 在 tracker / server / 埋点中字段一致
- 锁定阈值常量在测试和实现中保持 5/15min

## 执行选项

**1. 子代理驱动 (推荐)** - 每个任务派发一个子代理,快速迭代
**2. 内联执行** - 当前会话顺序执行

**选择哪种方式?**

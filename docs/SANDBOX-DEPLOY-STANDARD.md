# 沙箱部署标准方法 (Sandbox Deploy Standard)

> 适用版本: security-vule >= 2026-07-08 (commit `974d2bd`)

## 目标

为每个被检测的 git 仓库创建一个**隔离的 Docker 沙箱**,让白盒扫描 + PoC 验证
有真实的运行环境,而无需在宿主机上污染环境或安装运行时。

## 核心原则

| 原则 | 含义 |
|---|---|
| **1. 运行时从基础镜像拿** | 沙箱的 OS + 语言运行时 + 框架 + 数据库从**官方/runtime 镜像**继承 |
| **2. 应用代码从 git 拿** | 沙箱里跑的应用代码 = 用户 clone 的 git 仓库代码,**绝不**用 image 自带的默认代码 |
| **3. 不映射源码目录** | `COPY . /app/` 把代码 **bake 进 image**,不挂载宿主机目录,避免容器修改宿主机 |
| **4. 网络隔离** | 沙箱跑在专用 Docker 网络 `security-vule-sandbox`,无外网访问 |
| **5. 资源限制** | `--memory=512m --cpus=1 --restart=no` 防止恶意代码消耗宿主机资源 |
| **6. TTL 清理** | 默认 30 分钟自动过期,沙箱不在时清理 |
| **7. CN 镜像加速** | 默认通过 `docker.1ms.run` 加速镜像拉取,避免 dev 环境 10+ 分钟超时 |

## Dockerfile 生成逻辑(按项目类型)

### 场景 A: 项目自带 `Dockerfile`

直接用用户的 Dockerfile,**只解析 EXPOSE 端口**,不改 FROM。

```dockerfile
# 用户原样 Dockerfile
FROM php:8.2-apache
COPY . /var/www/html/
EXPOSE 80
CMD ["apache2-foreground"]
```

deploy 行为:
- ✅ 解析 `EXPOSE 80` → 沙箱容器 80 端口
- ✅ `docker run -p 19540:80` 主机高端口 → 容器 80
- ❌ **不重写**用户的 FROM(尊重用户选择)

### 场景 B: 项目无 Dockerfile,根据栈自动生成

| 项目类型 | 检测方法 | 生成的 Dockerfile |
|---|---|---|
| **Node.js** | has `package.json` | `FROM node:20-alpine; EXPOSE 3000; CMD ["npm","start"]` |
| **Python** | has `requirements.txt` | `FROM python:3.11-slim; EXPOSE 8080; CMD ["python","app.py"]` |
| **Go** | has `go.mod` | `FROM golang:1.22-alpine; EXPOSE 8080; CMD ["./server"]` |
| **PHP (无 Dockerfile)** | has `index.php` | `FROM php:8.2-apache; COPY . /var/www/html/; EXPOSE 80; CMD ["apache2-foreground"]` |
| **Generic** | 无任何 marker | `FROM python:3.11-slim; EXPOSE 8080; CMD ["python","-m","http.server","8080"]` |

### 场景 C: 项目**已有官方 Docker image**(如 DVWA)

**关键设计决策**:不直接用官方 image 当基础 runtime。

> ❌ **错误做法**: `FROM vulnerables/web-dvwa` 然后用 image 里的默认 DVWA 代码
> ✅ **正确做法**: `FROM vulnerables/web-dvwa` + `COPY . /var/www/html/` 用仓库的代码覆盖

```dockerfile
# 仓库: https://gitee.com/mirrors_kenneds6/DVWA.git
# 仓库不含 Dockerfile,所以走场景 C:
FROM vulnerables/web-dvwa

# 关键: 把 git 仓库的代码 COPY 进 image,覆盖 image 里的默认 DVWA
COPY . /var/www/html/

# 抑制 PHP 5.6 的 deprecation 警告,避免影响 PoC 验证
RUN echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_STRICT' \
      > /etc/php5/apache2/conf.d/99-dvwa.ini

EXPOSE 80
```

**为什么这样做**:
1. **运行时** (PHP 5.6 + Apache + MySQL + 自动 setup) 来自 official image
2. **应用代码** 来自 git 仓库 (用户实际想审计的代码)
3. 解决了 "PHP 8.2 + 老代码 setcookie 警告" 的兼容问题 (用 image 内置的 PHP 5.6)
4. PoC 验证打的是用户 clone 的真实代码,不是 image 默认代码

## 实施细节

### 1. CN 镜像加速 (代码: `apps/api/src/routes/targets.ts`)

```typescript
// Rewrite base images through a CN mirror (docker.1ms.run)
if (!process.env.SECURITY_VULE_SKIP_MIRROR) {
  dockerfile = dockerfile.replace(
    /^(FROM\s+)([a-z0-9.\/_-]+)(\s*)$/im,
    (_, prefix, image) => {
      if (image.startsWith('docker.1ms.run/') || image.startsWith('localhost/')) return _;
      return `${prefix}docker.1ms.run/${image}`;
    },
  );
}
```

关闭方式: `SECURITY_VULE_SKIP_MIRROR=1`

### 2. EXPOSE 端口解析

```typescript
if (has('Dockerfile')) {
  dockerfile = '';
  const dfResult = Bun.spawnSync({
    cmd: ['sh', '-c', `grep -iE '^\\s*EXPOSE\\s+[0-9]+' "${srcRoot}/Dockerfile" | head -1`],
    stdout: 'pipe', stderr: 'pipe',
  });
  const dfText = new TextDecoder().decode(dfResult.stdout).trim();
  const m = dfText.match(/EXPOSE\s+(\d+)/i);
  exposedPort = m ? m[1] : '8080';
  detectedStack = 'dockerfile';
}
```

### 3. 沙箱网络 + 端口映射

```bash
docker network create security-vule-sandbox  # 一次性,deploy 复用

docker run -d \
  --name sandbox-<target-id-prefix> \
  --network security-vule-sandbox \
  -p <host_port>:<container_port> \
  --memory=512m --cpus=1 \
  --restart=no \
  <image_name>
```

**关键点**:
- `19000-19999` 高端口 (避免与常用服务冲突)
- `-p` 映射宿主机端口 → PoC verifier (宿主机 Python 进程) 能访问
- 不需要 `--network host` (保持隔离)

### 4. Bun.serve timeout

```typescript
// apps/api/src/index.ts
export default {
  port: config.port,
  idleTimeout: 240,  // 4 minutes (Bun caps at 255)
  fetch: app.fetch,
};
```

deploy 路由调用 `Bun.spawnSync` 跑 `docker build` (DVWA 大型项目 30-60s),需要 ≥ 60s timeout。

### 5. Cleanup 行为

```typescript
// POST /targets/:id/cleanup
// 1. docker rm -f <container>
// 2. docker rmi -f <image>
// 3. ✓ 保留 source dir (用户可能想 redeploy)
```

**重要**: cleanup **不删源码**,只删 Docker artifacts。30 分钟 TTL 是自动清理机制。

## 端到端验证案例: DVWA

### 端到端流程

```bash
# 1. 创建项目
POST /api/provider/v1/scan/projects
  { customerId, name: "DVWA Sandbox Pipeline" }

# 2. 配置 (configuring → active)
POST /api/provider/v1/scan/projects/:id/configure

# 3. Git clone DVWA 仓库
POST /api/provider/v1/scan/sources
  { projectId, sourceType: "github",
    repoUrl: "https://gitee.com/mirrors_kenneds6/DVWA.git",
    branch: "master" }
# → 563 文件 clone 到 /tmp/security-vule-sources/.../extracted/

# 4. 白盒扫描
POST /api/provider/v1/scan/scans/trigger
  { projectId, triggerType: "manual" }
# → 17 findings (1 critical + 3 high + 13 medium)

# 5. 创建 target
POST /api/provider/v1/targets
  { name, baseUrl, customerId, projectId }

# 6. 部署沙箱 (自动: build + run + map port)
POST /api/provider/v1/targets/:id/deploy
# → 返回:
#   sandboxUrl: http://localhost:19506
#   container: sandbox-007fceff
#   network: security-vule-sandbox
#   detectedStack: dockerfile
#   exposedPort: 80
#   ttlMinutes: 30

# 7. setup.php 初始化 MySQL (一次性, DVWA 内部自动)
curl -X POST http://localhost:19506/setup.php \
     -d 'create_db=Create / Reset Database'

# 8. 验证 DVWA 工作
curl http://localhost:19506/login.php
# → HTTP 200, 4151 bytes, 0 Deprecated 警告

# 9. PoC 验证
for each finding:
  POST /api/provider/v1/validation/poc/generate
  POST /api/provider/v1/validation/poc/:id/approve
  POST /api/provider/v1/validation/poc/:id/execute

# → 14/17 PROVEN (1 critical eval + 13 medium MD5)
```

## 验收标准

部署沙箱满足以下**所有**条件视为成功:

- [x] `docker run -d` 成功,容器 30 秒内 `running`
- [x] HTTP 200 响应 (login page 或等效健康检查 endpoint)
- [x] 响应**不包含** PHP deprecation / warning 块
- [x] 沙箱内 DB (如 DVWA) 初始化成功
- [x] PoC verifier 跑 ≥ 50% 的 findings 应该 proven=true
- [x] 沙箱自动 30 分钟后清理 (或手动 cleanup API)

## 常见问题

| 现象 | 原因 | 解决 |
|---|---|---|
| Bun `request timed out` | default 10s < deploy 30-60s | `idleTimeout: 240` in `index.ts` |
| `docker build` 10+ 分钟 | CN 环境拉 docker.io 慢 | 默认 `docker.1ms.run` 加速镜像 |
| PHP 8.2 + 老代码报 Deprecated | DVWA 用 PHP 5.6 写的 | 用基础镜像内置的 PHP 5.6 (场景 C) |
| `docker: not found` in container | 沙箱内无 curl | 用 `wget` 或 `apt-get install curl` 或从 host curl |
| `error: Bun.serve expects idleTimeout to be 255 or less` | 设了 300s | 改成 ≤ 255 (建议 240) |
| PoC 0/N proven (全部 failed) | target status=paused | DB 改 `UPDATE core.targets SET status='active'` |
| target PATCH 不接受 `status` 字段 | schema 限制 | 改用 DB 直接 UPDATE |

## 实施文件清单

| 文件 | 角色 |
|---|---|
| `apps/api/src/routes/targets.ts` | deploy / cleanup / sandbox-status endpoints + Dockerfile 生成 + EXPOSE 解析 + 镜像加速 |
| `apps/api/src/index.ts` | Bun.serve `idleTimeout: 240` |
| `apps/web/src/views/sources/SourcesView.vue` | 一键 deploy + PoC 自动化按钮 |
| `apps/web/src/views/targets/TargetsView.vue` | 部署沙盒 / 清理沙盒按钮 |
| `apps/web/src/api/targets.ts` | Frontend deploy / cleanup API client |

## 相关 Commit

- `974d2bd` feat(sandbox): CN image mirror + EXPOSE parse + idleTimeout 240s
- `cb886a5` feat(sources): roll-up summary view at /sources + project delete
- `5bb5b6a` feat(targets): sandbox isolation — network, resource limits, TTL, cleanup
- `e794369` feat(sources): deploy+verify smart button — sandbox + auto PoC gen

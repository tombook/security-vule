# 安全评估业务闭环设计

## 全景图

```
客户(Customer)
  └── 项目(Project)
        ├── 代码源(Source) ─── zip 上传 / GitHub 关联
        │       │
        │       ├──→ 检测中心(Detection) ── 白盒 AST 扫描
        │       │         │
        │       │         └──→ 漏洞(Finding) ── critical/high/medium/low
        │       │                    │
        │       │                    └──→ PoC 验证(Validation)
        │       │                              │
        │       └──→ 目标管理(Target) ──── Docker 部署运行环境
        │                     │                  │
        │                     │    ←── PoC 利用 ──┘
        │                     │
        │                     └──→ exploit_proven = true → 漏洞状态 confirmed
        │
        └── 安全报告(Report) ── 汇总客户所有项目的漏洞 + PoC 结果
```

## 业务流（Step-by-Step 用户旅程）

### Step 1: 创建客户
- **页面**: `/customers` → 点击「+ 新建客户」
- **操作**: 填写客户名 / Slug / 联系人 / SLA
- **后端**: POST /customers → 自动创建 billing account (Starter plan)
- **完成标志**: 客户出现在列表，状态 = active

### Step 2: 创建项目 + 上传源码
- **入口**: 客户列表 → 点击客户 → 「新建项目」
- **页面**: `/projects/new` → 选择客户 → 填写项目名
- **自动跳转**: 创建后 → `/sources?project=<id>`
- **操作**: 拖拽 zip 上传源代码
- **后端**: POST /sources (multipart) → 解压 → 写 core.sources
- **完成标志**: 文件列表展示上传的代码，source status = active
- **下一步引导**: 页面显示「✅ 源码已就绪 → 下一步：触发白盒检测」

### Step 3: 白盒安全检测
- **入口 A**: 代码源页面 → 点击「触发扫描」
- **入口 B**: 检测中心 → 选择项目 → 触发扫描
- **后端**: POST /scans/trigger → runMockScan 异步执行
  - 读 upload_object_key 目录
  - 8 种漏洞模式正则匹配 (SQLi/XSS/CMDi/SSRF/Path/Secret/MD5/Eval)
  - 写入 detection.findings（含真实文件路径 + 行号）
- **完成标志**: 扫描状态 done，findings_total > 0
- **下一步引导**: 自动跳转 /findings?project=<id>

### Step 4: 部署 Docker 目标环境
- **入口 A**: 代码源页面 → 「部署为 Docker 目标」
- **入口 B**: 目标管理 → 「从源码部署」
- **操作**: 选择项目 → 系统自动:
  1. 读取上传的源码
  2. 检测语言/框架（package.json / requirements.txt / go.mod）
  3. 生成 Dockerfile + docker-compose.yml
  4. `docker build` + `docker run` 到随机端口
  5. 更新 core.targets.base_url = http://localhost:<port>
- **完成标志**: 目标 status = active, last_health = "ok (200) XXms"
- **下一步引导**: 「✅ 目标已运行 → 下一步：对漏洞执行 PoC 验证」

### Step 5: PoC 验证
- **入口 A**: 漏洞列表 → 点击「运行 PoC」
- **入口 B**: PoC 验证队列 → 查看已有 PoC run
- **操作（一键）**: generate → approve → execute
  - 选 finding → 按 CWE 匹配 verifier family
  - spawn python3 poc_verifier.py
  - 对 target.base_url 发送 exploit payload
  - 解析响应 → exploit_proven = true/false
- **完成标志**: PoC run status = success/failed, exploit_proven 写入
- **漏洞联动**: exploit_proven=true → finding.status 自动变为 confirmed

### Step 6: 安全报告
- **入口**: 客户详情 → 「安全报告」tab
- **内容**: 汇总该客户所有项目的漏洞统计 + PoC 验证结果
- **导出**: Markdown / PDF

## 状态机

### 项目状态
```
configuring ──→ active ──→ (scanning) ──→ active
                    │
                    └──→ paused ──→ active
                    │
                    └──→ archived (deleted_at)
```

### 漏洞状态
```
                 open
                   │
         ┌─────────┼─────────┐
         ↓         ↓         ↓
   in_progress  confirmed  false_positive
         │    (PoC 证实)   (人工驳回)
         ↓
       fixed
```

### PoC Run 状态
```
pending ──→ approved ──→ running ──→ success (exploit_proven=true)
                │           │
                │           ├──→ failed  (exploit_proven=false)
                │           └──→ error   (verifier 崩溃)
                │
                └──→ canceled (rejected)
```

### 目标状态
```
deploying ──→ active ──→ paused
                │
                └──→ broken (health check 连续失败)
                │
                └──→ retired (软删除)
```

## 页面间导航矩阵

| 当前页面 → | 客户 | 代码源 | 检测中心 | 漏洞 | 目标管理 | PoC 验证 |
|---|---|---|---|---|---|---|
| **客户详情** | - | 新建项目→自动跳 | - | 查看漏洞→跳 | - | - |
| **代码源** | 返回客户 | - | 触发扫描→跳 | 扫描完成→跳 | 部署目标→跳 | - |
| **检测中心** | - | 选择项目 | - | 扫描完成→跳 | - | - |
| **漏洞** | - | - | - | - | 需配置目标→跳 | 运行PoC→跳 |
| **目标管理** | - | 查看源码→跳 | - | - | - | 对漏洞验证→跳 |
| **PoC 验证** | - | - | - | 关联漏洞→跳 | 关联目标→跳 | - |

## 关键设计决策

### 为什么用「一键 PoC」而非手动流程
- 安全工程师的工作流是 "看到漏洞 → 想验证 → 立刻出结果"
- 手动 generate → approve → execute 三步太繁琐
- approve 步骤保留但折叠在背后（审计 trail 不丢）

### 为什么 Docker 部署在目标管理而非代码源
- 代码源是静态资产（可被多次扫描）
- 目标是运行时实体（有生命周期）
- 一个源码可以部署多个目标（dev/staging/prod）

### 为什么 PoC verifier 用 Python 而非 JS
- 安全社区 Python 工具链成熟（requests/sqlmap/pwntools）
- exploit payload 常为 Python 脚本
- 与 LLM 生成 PoC 的天然对齐

/**
 * security-vule UI pages — HTML/CSS/JS 页面渲染
 *
 * 设计系统：
 * - 暗色主题，适配安全工具场景
 * - 原生 HTML + 少量 vanilla JS，无框架依赖
 * - 所有状态通过 URL/JSON 传递，支持分享链接
 */

import type { VulnerabilityFinding } from '../engine/analyzer.js';

// 共享的 HTML 头部
const SHARED_HEAD = (title: string, port: number): string => `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · security-vule</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='80' font-size='80'>🌌</text></svg>">
<style>
:root {
 --bg: #0d1117;
 --bg-elevated: #161b22;
 --bg-overlay: #1c2128;
 --border: #30363d;
 --border-muted: #21262d;
 --text-primary: #e6edf3;
 --text-secondary: #8b949e;
 --text-muted: #6e7681;
 --accent: #58a6ff;
 --accent-hover: #79b8ff;
 --critical: #f85149;
 --critical-bg: rgba(248,81,73,0.1);
 --high: #ff7b72;
 --high-bg: rgba(255,123,114,0.1);
 --medium: #d29922;
 --medium-bg: rgba(210,153,34,0.1);
 --low: #56d364;
 --success: #2ea043;
 --radius: 6px;
 --shadow: 0 1px 0 rgba(0,0,0,0.1);
 --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { background: var(--bg); }
body {
 font-family: var(--font);
 background: var(--bg);
 color: var(--text-primary);
 line-height: 1.5;
 -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
pre { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; overflow-x: auto; font-size: 13px; }

/* 头部导航 */
.header {
 position: sticky; top: 0; z-index: 100;
 background: rgba(13,17,23,0.85);
 backdrop-filter: blur(8px);
 border-bottom: 1px solid var(--border-muted);
 padding: 12px 24px;
 display: flex; align-items: center; justify-content: space-between;
}
.logo { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 16px; }
.logo-icon { font-size: 20px; }
.nav { display: flex; gap: 4px; }
.nav a {
 color: var(--text-secondary);
 padding: 6px 12px;
 border-radius: var(--radius);
 font-size: 14px;
 font-weight: 500;
}
.nav a:hover { color: var(--text-primary); background: var(--bg-overlay); text-decoration: none; }
.nav a.active { color: var(--text-primary); background: var(--bg-overlay); }
.header-actions { display: flex; gap: 8px; align-items: center; }

/* 按钮 */
.btn {
 display: inline-flex; align-items: center; gap: 6px;
 background: var(--accent); color: #fff;
 padding: 8px 16px; border-radius: var(--radius); border: none;
 font-size: 14px; font-weight: 500; cursor: pointer;
 transition: background 0.15s;
 text-decoration: none;
}
.btn:hover { background: var(--accent-hover); text-decoration: none; color: #fff; }
.btn-secondary { background: var(--bg-elevated); color: var(--text-primary); border: 1px solid var(--border); }
.btn-secondary:hover { background: var(--bg-overlay); border-color: var(--text-muted); color: var(--text-primary); }
.btn-danger { background: var(--critical); }
.btn-danger:hover { background: #ff6b62; color: #fff; }
.btn-large { padding: 12px 24px; font-size: 15px; }
.btn-sm { padding: 4px 10px; font-size: 13px; }

/* 布局 */
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
.container-wide { max-width: 1400px; margin: 0 auto; padding: 24px; }
.hero { padding: 48px 24px 64px; max-width: 1200px; margin: 0 auto; text-align: center; }
.hero h1 { font-size: 48px; line-height: 1.15; margin-bottom: 16px; letter-spacing: -0.02em; }
.hero .sub { font-size: 20px; color: var(--text-secondary); margin-bottom: 32px; max-width: 680px; margin-left: auto; margin-right: auto; }
.section-title { font-size: 24px; margin-bottom: 16px; }
.section-sub { color: var(--text-secondary); margin-bottom: 24px; }

/* 卡片 */
.card {
 background: var(--bg-elevated);
 border: 1px solid var(--border);
 border-radius: var(--radius);
 padding: 20px;
 transition: border-color 0.15s;
}
.card:hover { border-color: var(--text-muted); }
.card h3 { font-size: 16px; margin-bottom: 8px; }
.card p { color: var(--text-secondary); font-size: 14px; }
.card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }

/* 严重程度标签 */
.badge {
 display: inline-block;
 padding: 2px 8px;
 border-radius: 999px;
 font-size: 11px;
 font-weight: 600;
 text-transform: uppercase;
 letter-spacing: 0.04em;
}
.badge-CRITICAL { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
.badge-HIGH { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
.badge-MEDIUM { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }
.badge-LOW { background: rgba(86,211,100,0.1); color: var(--low); border: 1px solid var(--low); }

/* 统计卡片 */
.stat-card {
 display: flex; flex-direction: column; gap: 4px;
 padding: 16px 20px;
 border-left: 4px solid var(--border);
 background: var(--bg-elevated);
 border-radius: var(--radius);
}
.stat-card.critical { border-left-color: var(--critical); }
.stat-card.high { border-left-color: var(--high); }
.stat-card.medium { border-left-color: var(--medium); }
.stat-card.low { border-left-color: var(--low); }
.stat-card .num { font-size: 32px; font-weight: 700; line-height: 1; }
.stat-card .label { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }

/* 表格 */
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; padding: 8px 12px; background: var(--bg-elevated); color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; border-bottom: 1px solid var(--border); }
td { padding: 10px 12px; border-bottom: 1px solid var(--border-muted); }
tr:hover td { background: var(--bg-elevated); }

/* 表单 */
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 6px; font-size: 13px; color: var(--text-secondary); }
.form-group input, .form-group select, .form-group textarea {
 width: 100%;
 background: var(--bg-elevated);
 border: 1px solid var(--border);
 color: var(--text-primary);
 padding: 8px 12px;
 border-radius: var(--radius);
 font-size: 14px;
 font-family: inherit;
}
.form-group input:focus, .form-group textarea:focus { outline: none; border-color: var(--accent); }
.form-group textarea { min-height: 200px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-actions { display: flex; gap: 12px; align-items: center; }

/* 拖放区域 */
.dropzone {
 border: 2px dashed var(--border);
 border-radius: var(--radius);
 padding: 40px;
 text-align: center;
 background: var(--bg-elevated);
 cursor: pointer;
 transition: all 0.15s;
}
.dropzone:hover, .dropzone.dragover { border-color: var(--accent); background: var(--bg-overlay); }
.dropzone p { color: var(--text-secondary); margin-top: 8px; font-size: 14px; }

/* 标签页 */
.tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
.tab {
 padding: 10px 16px;
 color: var(--text-secondary);
 cursor: pointer;
 border-bottom: 2px solid transparent;
 font-size: 14px;
 font-weight: 500;
}
.tab:hover { color: var(--text-primary); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* 进度条 */
.progress { height: 4px; background: var(--bg-elevated); border-radius: 999px; overflow: hidden; margin: 12px 0; }
.progress-bar { height: 100%; background: var(--accent); transition: width 0.3s; }

/* 空状态 */
.empty {
 text-align: center;
 padding: 60px 20px;
 color: var(--text-secondary);
}
.empty h3 { color: var(--text-primary); margin-bottom: 8px; }

/* 页脚 */
.footer {
 padding: 32px 24px;
 border-top: 1px solid var(--border-muted);
 color: var(--text-muted);
 font-size: 13px;
 text-align: center;
}

/* 行内代码 */
code.inline {
 background: var(--bg-elevated);
 padding: 2px 6px;
 border-radius: 3px;
 font-size: 13px;
 border: 1px solid var(--border-muted);
}

/* 漏洞卡片（报告页） */
.finding-card {
 background: var(--bg-elevated);
 border: 1px solid var(--border);
 border-radius: var(--radius);
 padding: 16px 20px;
 margin-bottom: 12px;
}
.finding-card .finding-header {
 display: flex; align-items: center; gap: 12px;
 margin-bottom: 8px;
}
.finding-card .finding-title {
 font-size: 16px; font-weight: 600;
 flex: 1;
}
.finding-card .finding-meta {
 font-size: 13px; color: var(--text-secondary);
 margin-bottom: 8px;
}
.finding-card .finding-meta code {
 background: var(--bg-overlay); padding: 2px 6px; border-radius: 3px;
}
.finding-card .finding-desc {
 font-size: 14px; color: var(--text-secondary);
 margin-bottom: 8px;
}
.finding-card .confidence-bar {
 height: 6px; background: var(--bg-overlay); border-radius: 999px;
 margin-top: 8px; overflow: hidden;
}
.finding-card .confidence-fill {
 height: 100%; background: var(--accent);
 transition: width 0.3s;
}

/* CTA 横幅 */
.cta-banner {
 background: linear-gradient(135deg, #1c2128 0%, #161b22 100%);
 border: 1px solid var(--border);
 border-radius: var(--radius);
 padding: 32px;
 margin: 24px 0;
 text-align: center;
}
.cta-banner h2 { font-size: 24px; margin-bottom: 8px; }
.cta-banner p { color: var(--text-secondary); margin-bottom: 16px; }

/* 信任栏 */
.trust-strip { display: flex; flex-wrap: wrap; gap: 24px; justify-content: center; padding: 16px; color: var(--text-muted); font-size: 13px; margin-top: 24px; }
.trust-strip span { display: inline-flex; align-items: center; gap: 6px; }
.trust-strip .check { color: var(--low); }

/* 工具类 */
.text-muted { color: var(--text-secondary); }
.text-center { text-align: center; }
.mt-1 { margin-top: 8px; } .mt-2 { margin-top: 16px; } .mt-3 { margin-top: 24px; } .mt-4 { margin-top: 32px; }
.mb-1 { margin-bottom: 8px; } .mb-2 { margin-bottom: 16px; } .mb-3 { margin-bottom: 24px; }
.flex { display: flex; } .gap-2 { gap: 8px; } .gap-3 { gap: 16px; } .items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.hidden { display: none; }
</style>
</head>
<body>
${HEADER(port)}
<div class="container">
`;

// 共享的 HTML 底部
const SHARED_FOOT = (): string => `
</div>
<div class="footer">
 security-vule v1.0.0 · <a href="/healthz">/healthz</a> · AGPL-3.0
</div>
<script>
 // 标签页切换
 document.querySelectorAll('[data-tab]').forEach(t => t.addEventListener('click', () => {
 document.querySelectorAll('[data-tab]').forEach(x => x.classList.remove('active'));
 document.querySelectorAll('[data-panel]').forEach(x => x.classList.remove('active'));
 t.classList.add('active');
 document.querySelector('[data-panel="' + t.dataset.tab + '"]').classList.add('active');
 }));
</script>
</body>
</html>`;

// 头部导航
function HEADER(port: number): string {
  return `<div class="header">
 <div class="logo">
 <span class="logo-icon">🌌</span>
 <a href="/" style="color: var(--text-primary); text-decoration: none;">security-vule</a>
 </div>
 <nav class="nav">
 <a href="/">首页</a>
 <a href="/scan">扫描</a>
 <a href="/settings">设置</a>
 </nav>
 <div class="header-actions">
 <a class="btn btn-secondary btn-sm" href="https://github.com/security-vule/security-vule" target="_blank">GitHub ↗</a>
 </div>
</div>`;
}

/**
 * 渲染首页
 */
export function renderLanding(port: number): string {
  return (
    SHARED_HEAD('首页', port) +
    `
 <section class="hero">
 <h1>在 60 秒内发现代码中的 <span style="color: var(--accent);">安全漏洞</span></h1>
 <p class="sub">基于数据驱动的白盒漏洞挖掘系统，支持多语言、多维度分析，提供可操作的修复建议。</p>
 <div class="form-actions" style="justify-content: center;">
 <a href="/scan" class="btn btn-large">开始扫描 →</a>
 <a href="/scan#upload" class="btn btn-secondary btn-large">上传代码</a>
 </div>
 <div class="trust-strip">
 <span><span class="check">✓</span> 多语言支持</span>
 <span><span class="check">✓</span> CPG 代码属性图</span>
 <span><span class="check">✓</span> 污点分析</span>
 <span><span class="check">✓</span> 异常检测</span>
 <span><span class="check">✓</span> 开源 AGPL-3.0</span>
 </div>
 </section>

 <section class="container-wide mt-4">
 <h2 class="section-title">核心能力</h2>
 <p class="section-sub">不是黑盒 AI 评分，每个发现都基于严谨的代码分析。</p>
 <div class="card-grid mt-2">
 <div class="card">
 <h3>🌐 多语言支持</h3>
 <p>支持 PHP、Python、JavaScript、TypeScript、Java、Go 等多种编程语言的漏洞检测。</p>
 </div>
 <div class="card">
 <h3>🔬 CPG 代码属性图</h3>
 <p>构建代码属性图（CPG），结合 AST、CFG、DFG 进行深度语义分析，精准定位漏洞。</p>
 </div>
 <div class="card">
 <h3>🎯 污点传播分析</h3>
 <p>追踪从污染源（用户输入）到汇聚点（危险函数）的完整路径，减少误报。</p>
 </div>
 <div class="card">
 <h3>📊 异常检测</h3>
 <p>基于统计异常检测算法，识别代码中的异常模式，发现潜在的未知漏洞。</p>
 </div>
 <div class="card">
 <h3>🛡️ CWE 映射</h3>
 <p>所有漏洞都映射到标准 CWE 编号，便于理解漏洞原理和修复方法。</p>
 </div>
 <div class="card">
 <h3>⚡ 快速扫描</h3>
 <p>优化的分析引擎，单文件扫描仅需数秒，适合集成到 CI/CD 流水线。</p>
 </div>
 </div>
 </section>

 <section class="cta-banner">
 <h2>准备好扫描你的代码了吗？</h2>
 <p>免费、开源、无需注册。</p>
 <a href="/scan" class="btn btn-large">运行第一次扫描 →</a>
 </section>

 <section class="container-wide mt-4">
 <h2 class="section-title">漏洞类型覆盖</h2>
 <p class="section-sub">覆盖 OWASP Top 10 及常见的代码安全问题：</p>
 <table>
 <thead><tr><th>漏洞类型</th><th>严重程度</th><th>支持语言</th></tr></thead>
 <tbody>
 <tr><td>SQL 注入</td><td><span class="badge badge-CRITICAL">CRITICAL</span></td><td>PHP, Python, JS/TS</td></tr>
 <tr><td>命令注入</td><td><span class="badge badge-CRITICAL">CRITICAL</span></td><td>PHP, Python, JS/TS</td></tr>
 <tr><td>XSS 跨站脚本</td><td><span class="badge badge-HIGH">HIGH</span></td><td>PHP, JS/TS</td></tr>
 <tr><td>文件包含</td><td><span class="badge badge-HIGH">HIGH</span></td><td>PHP</td></tr>
 <tr><td>硬编码凭证</td><td><span class="badge badge-HIGH">HIGH</span></td><td>全部</td></tr>
 <tr><td>弱加密算法</td><td><span class="badge badge-MEDIUM">MEDIUM</span></td><td>全部</td></tr>
 </tbody>
 </table>
 </section>
 ${SHARED_FOOT()}`
  );
}

/**
 * 渲染扫描页面
 */
export function renderScanPage(port: number): string {
  return (
    SHARED_HEAD('扫描', port) +
    `
 <h1 class="section-title">运行扫描</h1>
 <p class="section-sub">三种扫描方式：上传文件、粘贴代码、或使用示例代码。</p>

 <div class="tabs">
 <div class="tab active" data-tab="upload">📁 上传文件</div>
 <div class="tab" data-tab="paste">📋 粘贴代码</div>
 <div class="tab" data-tab="sample">🧪 示例代码</div>
 </div>

 <div class="tab-panel active" data-panel="upload">
 <form id="upload-form">
 <div class="dropzone" id="drop">
 <p style="font-size: 18px;"><strong>拖放文件到这里</strong></p>
 <p>或点击选择 · 最大 1 MB · 支持 .php / .py / .js / .ts 等</p>
 <input type="file" id="file" accept=".php,.py,.js,.jsx,.ts,.tsx,.java,.go,.c,.cpp,.rs" style="display:none">
 </div>
 <div class="form-group mt-2">
 <label>编程语言</label>
 <select name="language" id="lang">
 <option value="auto">自动检测</option>
 <option value="php">PHP</option>
 <option value="python">Python</option>
 <option value="javascript">JavaScript</option>
 <option value="typescript">TypeScript</option>
 <option value="java">Java</option>
 <option value="go">Go</option>
 </select>
 </div>
 <div class="form-actions">
 <button type="submit" class="btn btn-large">开始扫描</button>
 <span id="upload-status" class="text-muted"></span>
 </div>
 </form>
 </div>

 <div class="tab-panel" data-panel="paste">
 <form id="paste-form">
 <div class="form-group">
 <label>粘贴代码</label>
 <textarea name="code" placeholder="// 在此粘贴要扫描的代码..."></textarea>
 </div>
 <div class="form-group">
 <label>编程语言</label>
 <select name="language">
 <option value="php">PHP</option>
 <option value="python">Python</option>
 <option value="javascript">JavaScript</option>
 <option value="typescript">TypeScript</option>
 <option value="java">Java</option>
 <option value="go">Go</option>
 </select>
 </div>
 <div class="form-actions">
 <button type="submit" class="btn btn-large">开始扫描</button>
 <span id="paste-status" class="text-muted"></span>
 </div>
 </form>
 </div>

 <div class="tab-panel" data-panel="sample">
 <p class="text-muted mb-2">试试这个存在 SQL 注入漏洞的 PHP 示例代码：</p>
 <pre><code>&lt;?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $id;
$result = mysql_query($query);
echo $result;
?&gt;</code></pre>
 <div class="form-actions mt-2">
 <button class="btn btn-large" id="run-sample">运行示例扫描</button>
 <span id="sample-status" class="text-muted"></span>
 </div>
 </div>

 <script>
 // 拖放上传
 const drop = document.getElementById('drop');
 const fileInput = document.getElementById('file');
 if (drop) {
 drop.addEventListener('click', () => fileInput.click());
 drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('dragover'); });
 drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
 drop.addEventListener('drop', e => {
 e.preventDefault();
 drop.classList.remove('dragover');
 if (e.dataTransfer.files[0]) {
 fileInput.files = e.dataTransfer.files;
 document.getElementById('upload-form').requestSubmit();
 }
 });
 }

 function startScan(formData, statusEl) {
 statusEl.textContent = '扫描中...';
 fetch('/api/scan', { method: 'POST', body: formData })
 .then(r => r.json().then(b => ({ ok: r.ok, b })))
 .then(({ ok, b }) => {
 if (ok) {
 statusEl.textContent = '✅ 扫描完成，正在打开报告...';
 window.location.href = b.reportUrl;
 } else {
 statusEl.textContent = '❌ ' + (b.error || '扫描失败');
 }
 })
 .catch(e => { statusEl.textContent = '❌ ' + e.message; });
 }

 // 上传表单
 const uploadForm = document.getElementById('upload-form');
 if (uploadForm) uploadForm.addEventListener('submit', e => {
 e.preventDefault();
 const fd = new FormData();
 const file = fileInput.files[0];
 if (!file) return;
 fd.append('file', file);
 fd.append('language', document.getElementById('lang').value);
 startScan(fd, document.getElementById('upload-status'));
 });

 // 粘贴表单
 const pasteForm = document.getElementById('paste-form');
 if (pasteForm) pasteForm.addEventListener('submit', e => {
 e.preventDefault();
 const fd = new FormData(pasteForm);
 fd.append('target', 'pasted-code');
 startScan(fd, document.getElementById('paste-status'));
 });

 // 示例扫描
 const runSample = document.getElementById('run-sample');
 if (runSample) runSample.addEventListener('click', () => {
 const code = '<?php\\n$id = $_GET[\\'id\\'];\\n$query = "SELECT * FROM users WHERE id=" . $id;\\n$result = mysql_query($query);\\necho $result;\\n?>';
 const fd = new FormData();
 fd.append('code', code);
 fd.append('language', 'php');
 fd.append('target', 'sample-sqli.php');
 startScan(fd, document.getElementById('sample-status'));
 });
 </script>
 ${SHARED_FOOT()}`
  );
}

interface ReportJob {
  id: string;
  target: string;
  language: string;
  status: string;
  startedAt: number;
  finishedAt?: number;
  findings?: VulnerabilityFinding[];
  filesScanned?: number;
  error?: string;
}

/**
 * 渲染报告页面
 */
export function renderReport(job: ReportJob, port: number): string {
  const findings = job.findings || [];
  
  // 统计各严重程度数量
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity as keyof typeof counts]++;
    }
  }

  return (
    SHARED_HEAD('扫描报告', port) +
    `
 <div class="flex justify-between items-center mb-3">
 <div>
 <h1 style="font-size: 24px; margin-bottom: 4px;">扫描报告</h1>
 <div class="text-muted" style="font-size: 13px;">
 目标: <code class="inline">${escapeHtml(job.target)}</code> · 
 语言: ${escapeHtml(job.language)} · 
 状态: ${job.status}
 </div>
 </div>
 <div class="flex gap-2">
 <a href="/scan" class="btn btn-secondary">新建扫描</a>
 <a href="/api/scan/${job.id}" class="btn btn-secondary">JSON</a>
 </div>
 </div>

 <div class="card-grid mb-3">
 <div class="stat-card critical">
 <div class="num">${counts.CRITICAL}</div>
 <div class="label">严重</div>
 </div>
 <div class="stat-card high">
 <div class="num">${counts.HIGH}</div>
 <div class="label">高危</div>
 </div>
 <div class="stat-card medium">
 <div class="num">${counts.MEDIUM}</div>
 <div class="label">中危</div>
 </div>
 <div class="stat-card low">
 <div class="num">${counts.LOW}</div>
 <div class="label">低危</div>
 </div>
 </div>

 ${
   counts.CRITICAL === 0 && counts.HIGH === 0
     ? `
 <div class="cta-banner">
 <h2 style="color: var(--low);">✅ 未发现严重或高危漏洞</h2>
 <p>你的代码通过了最严格的检查。请查看下方的中危和低危发现。</p>
 </div>
 `
     : `
 <div class="cta-banner">
 <h2 style="color: var(--critical);">⚠️ 发现 ${counts.CRITICAL} 个严重、${counts.HIGH} 个高危漏洞</h2>
 <p>请优先处理严重和高危漏洞。每个漏洞卡片包含详细说明和修复建议。</p>
 </div>
 `
 }

 <h2 class="section-title">漏洞列表 (${findings.length})</h2>
 <p class="section-sub">按严重程度排序。</p>

 <div class="mt-2">
 ${
   findings.length === 0
     ? `
 <div class="empty">
 <h3>未发现漏洞</h3>
 <p>你的代码没有触发已知的漏洞模式。继续保持良好的编码习惯！</p>
 </div>
 `
     : findings
         .map((f) => {
           const eid = encodeURIComponent(f.id);
           return `<div class="finding-card">
 <div class="finding-header">
 <span class="badge badge-${f.severity}">${f.severity}</span>
 <span class="finding-title">${escapeHtml(f.title)}</span>
 <span style="font-size: 13px; color: var(--text-muted);">置信度: ${Math.round(f.confidence * 100)}%</span>
 </div>
 <div class="finding-meta">
 ${escapeHtml(f.file)}:<strong>${f.line}</strong>
 ${f.cwe ? ` · CWE: <code class="inline">${escapeHtml(f.cwe)}</code>` : ''}
 · 类型: <code class="inline">${escapeHtml(f.type)}</code>
 </div>
 <div class="finding-desc">${escapeHtml(f.description)}</div>
 <div class="confidence-bar">
 <div class="confidence-fill" style="width: ${Math.round(f.confidence * 100)}%"></div>
 </div>
 </div>`;
         })
         .join('\n')
 }
 </div>

 ${SHARED_FOOT()}`
  );
}

/**
 * 渲染设置页面
 */
export function renderSettings(port: number): string {
  return (
    SHARED_HEAD('设置', port) +
    `
 <h1 class="section-title">设置</h1>
 <p class="section-sub">配置扫描行为、LLM 提供商和集成选项。</p>

 <div class="card-grid mt-2">
 <div class="card">
 <h3>🤖 LLM 提供商</h3>
 <p>选择用于 LLM 增强扫描的模型提供商。</p>
 <div class="form-group mt-2">
 <label>主要提供商</label>
 <select>
 <option>OpenAI (默认)</option>
 <option>Anthropic Claude</option>
 <option>Google Gemini</option>
 <option>Ollama (本地)</option>
 </select>
 </div>
 <p class="text-muted" style="font-size: 12px;">通过环境变量设置 API Key（如 <code class="inline">OPENAI_API_KEY</code>）</p>
 </div>

 <div class="card">
 <h3>🎯 扫描模式</h3>
 <p>两种扫描模式可选：</p>
 <ul style="margin-left: 20px; color: var(--text-secondary); font-size: 14px;">
 <li><strong>基础模式</strong>：快速扫描，基于规则和静态分析</li>
 <li><strong>LLM 增强</strong>：更高召回率，需 LLM API 调用</li>
 </ul>
 </div>

 <div class="card">
 <h3>📤 输出格式</h3>
 <p>支持多种输出格式：</p>
 <ul style="margin-left: 20px; color: var(--text-secondary); font-size: 14px;">
 <li>JSON - 结构化数据</li>
 <li>SARIF - GitHub Code Scanning</li>
 <li>HTML - 可视化报告</li>
 <li>Markdown - 文档格式</li>
 </ul>
 </div>

 <div class="card">
 <h3>🔌 集成方式</h3>
 <p>多种集成方式适配你的工作流：</p>
 <ul style="margin-left: 20px; color: var(--text-secondary); font-size: 14px;">
 <li>CLI 命令行工具</li>
 <li>GitHub Actions</li>
 <li>GitLab CI</li>
 <li>MCP 服务器（AI Agent 集成）</li>
 </ul>
 </div>

 <div class="card">
 <h3>📊 健康检查</h3>
 <p>监控服务运行状态：</p>
 <div class="form-actions mt-2">
 <button class="btn btn-secondary btn-sm" onclick="fetch('/healthz').then(r=>r.json()).then(j=>alert(JSON.stringify(j,null,2)))">检查状态</button>
 </div>
 </div>

 <div class="card">
 <h3>🔒 隐私保护</h3>
 <p>所有扫描在本地执行，代码不会上传到外部服务器。</p>
 <p class="text-muted" style="font-size: 12px; margin-top: 8px;">
 LLM 增强模式下会将代码片段发送到配置的 LLM 提供商进行分析。
 </p>
 </div>
 </div>

 ${SHARED_FOOT()}`
  );
}

/**
 * 渲染错误页面
 */
export function renderError(title: string, detail: string): string {
  return (
    SHARED_HEAD(title, 3001) +
    `
 <div class="empty">
 <h3>${escapeHtml(title)}</h3>
 <p>${escapeHtml(detail)}</p>
 <a href="/" class="btn mt-2">返回首页</a>
 </div>
 ${SHARED_FOOT()}`
  );
}

// HTML 转义
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

<template>
  <div class="sources-page" v-loading="loading">
    <header class="page-header">
      <h2>代码源管理</h2>
      <p class="subtitle">上传 zip · 关联 GitHub · 触发白盒扫描 · 部署目标环境</p>
    </header>

    <!-- ── 项目选择区 ──────────────────────────────── -->
    <el-card shadow="never" class="project-card">
      <div class="project-bar">
        <el-select
          v-model="projectId"
          placeholder="选择项目"
          filterable
          style="width: 360px"
          @change="onProjectChange"
        >
          <el-option
            v-for="p in projects"
            :key="p.id"
            :label="`${p.name} (${p.status})`"
            :value="p.id"
          />
        </el-select>
        <el-button @click="loadProjects" :icon="Refresh">刷新</el-button>
        <el-button type="primary" :icon="Plus" @click="goNewProject">新建项目</el-button>
      </div>
    </el-card>

    <!-- ── 无项目引导 ──────────────────────────────── -->
    <el-empty
      v-if="projects.length === 0 && !loading"
      description="还没有项目 — 新建一个项目来开始安全评估"
    >
      <el-button type="primary" @click="goNewProject">+ 新建项目</el-button>
    </el-empty>

    <!-- ── 有项目但未选 ──────────────────────────────── -->
    <el-empty
      v-else-if="!projectId && projects.length > 0"
      description="请从上方下拉选择一个项目"
    />

    <!-- ── 项目主面板 ──────────────────────────────── -->
    <template v-else-if="projectId">
      <!-- 源码信息卡片（已有 source 时显示） -->
      <el-card v-if="source" shadow="never" class="source-info">
        <template #header>
          <div class="card-header">
            <div class="source-meta">
              <el-tag :type="source.sourceType === 'upload' ? 'success' : 'info'" size="small">
                {{ source.sourceType === 'upload' ? 'zip 上传' : source.sourceType }}
              </el-tag>
              <span class="meta-text">分支: {{ source.branch }}</span>
              <span class="meta-text">状态: {{ source.status }}</span>
              <span class="meta-text" v-if="fileCount > 0">{{ fileCount }} 个文件</span>
            </div>
            <div>
              <el-button type="danger" size="small" :icon="Delete" @click="onDeleteSource" plain>删除源</el-button>
            </div>
          </div>
        </template>

        <!-- 上传新版本（覆盖） -->
        <el-upload
          drag
          :auto-upload="true"
          :http-request="onUpload"
          :show-file-list="false"
          accept=".zip"
          class="upload-mini"
        >
          <div class="upload-hint-mini">
            <el-icon :size="20"><UploadFilled /></el-icon>
            <span>拖拽新 zip 上传（替换现有源码）</span>
          </div>
        </el-upload>

        <!-- 文件列表 -->
        <div class="file-section" v-if="files.length > 0">
          <div class="file-header">
            <strong>文件列表 ({{ files.length }})</strong>
            <el-input v-model="fileFilter" placeholder="过滤文件路径..." clearable style="width: 300px" size="small" />
          </div>
          <el-table :data="filteredFiles" max-height="400" stripe size="small">
            <el-table-column label="路径" min-width="400">
              <template #default="{ row }">
                <code class="path">{{ relativePath(row) }}</code>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="80">
              <template #default="{ row }">
                <el-button link type="primary" size="small" @click="preview(row)">预览</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>

      <!-- 无 source — 首次上传区 -->
      <el-card v-else shadow="never" class="upload-card">
        <el-upload
          drag
          :auto-upload="true"
          :http-request="onUpload"
          :show-file-list="false"
          accept=".zip"
        >
          <div class="upload-hint">
            <el-icon :size="48"><UploadFilled /></el-icon>
            <div class="upload-title">拖拽 zip 文件到此处，或点击上传</div>
            <div class="muted">上传源代码压缩包，系统将自动解压用于白盒分析和 Docker 部署</div>
          </div>
        </el-upload>

        <!-- GitHub 关联（Phase 1 占位） -->
        <el-divider>或</el-divider>
        <div class="github-zone">
          <el-button :icon="Link" @click="showGithub = true" plain>关联 GitHub / GitLab 仓库</el-button>
        </div>
      </el-card>

      <!-- ── 下一步操作区（源码就绪后显示） ──────────── -->
      <div class="next-steps" v-if="source">
        <el-card shadow="never" class="next-card">
          <template #header>
            <div class="next-header">
              <strong>下一步操作</strong>
              <el-tag size="small" type="info" effect="plain">
                一个按钮串行触发: 扫描 → 沙盒 → PoC
              </el-tag>
            </div>
          </template>
          <div class="step-buttons">
            <el-button type="primary" size="large" :icon="VideoPlay" @click="onScan" :loading="scanning">
              触发白盒安全检测
              <span class="sub">→ 扫描任务 → 漏洞列表</span>
            </el-button>
            <el-button
              type="success"
              size="large"
              :icon="Aim"
              @click="onDeployAndVerify"
              :loading="deploying || pocGenerating"
            >
              部署 Docker 目标环境 + 生成 PoC 任务
              <span class="sub">
                {{ deploying ? '沙盒部署中...' : pocGenerating ? '生成 PoC 任务中...' : '→ 沙盒任务 → PoC 队列' }}
              </span>
            </el-button>
            <el-button size="large" :icon="Warning" @click="router.push(`/findings?project=${projectId}`)">
              查看漏洞列表
            </el-button>
          </div>

          <el-alert
            v-if="pocGenerating"
            type="info"
            :closable="false"
            show-icon
            class="poc-progress"
          >
            正在为每个 open 状态的漏洞生成 PoC 验证任务，生成完成后自动跳转到 PoC 队列。
          </el-alert>
        </el-card>
      </div>
    </template>

    <!-- 文件预览弹窗 -->
    <el-dialog v-model="previewOpen" :title="`预览: ${previewPath}`" width="800" top="5vh">
      <pre class="preview-body">{{ previewContent }}</pre>
    </el-dialog>

    <!-- GitHub / GitLab 关联弹窗 -->
    <el-dialog v-model="showGithub" title="关联 Git 仓库" width="540">
      <el-form :model="gitForm" label-width="100" @submit.prevent="connectGit">
        <el-form-item label="仓库 URL" required>
          <el-input
            v-model="gitForm.repoUrl"
            placeholder="https://github.com/org/repo.git"
          />
        </el-form-item>
        <el-form-item label="平台">
          <el-radio-group v-model="gitForm.sourceType">
            <el-radio-button value="github">GitHub</el-radio-button>
            <el-radio-button value="gitlab">GitLab</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="分支">
          <el-input v-model="gitForm.branch" placeholder="main" />
        </el-form-item>
        <el-form-item label="Access Token">
          <el-input
            v-model="gitForm.accessToken"
            type="password"
            show-password
            placeholder="ghp_... / glpat-... (私有仓库必填，公开仓库可留空)"
          />
          <div class="form-hint muted">
            Token 仅用于 git clone，加密存储，不会出现在 URL 日志中。
            GitHub: Settings → Developer settings → Personal access tokens
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showGithub = false">取消</el-button>
        <el-button
          type="primary"
          :loading="gitConnecting"
          :disabled="!gitForm.repoUrl"
          @click="connectGit"
        >关联并 Clone</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import {
  VideoPlay, UploadFilled, Plus, Refresh, Delete, Link, Aim, Warning,
} from '@element-plus/icons-vue';
import * as scanApi from '@/api/scan';
import * as api from '@/api/targets';
import { apiClient } from '@/api/client';
import type { ScanProject } from '@/api/scan';

const route = useRoute();
const router = useRouter();

// ── State ──────────────────────────────────────
const loading = ref(false);
const scanning = ref(false);
const projects = ref<ScanProject[]>([]);
const projectId = ref('');
const source = ref<any>(null);
const files = ref<string[]>([]);
const fileCount = ref(0);
const rootPath = ref('');
const fileFilter = ref('');

const previewOpen = ref(false);
const previewContent = ref('');
const previewPath = ref('');
const showGithub = ref(false);
const gitConnecting = ref(false);
const gitForm = reactive({
  repoUrl: '',
  sourceType: 'github' as 'github' | 'gitlab',
  branch: 'main',
  accessToken: '',
});

const filteredFiles = computed(() => {
  if (!fileFilter.value) return files.value;
  const f = fileFilter.value.toLowerCase();
  return files.value.filter((p: string) => p.toLowerCase().includes(f));
});

function relativePath(fullPath: string) {
  if (rootPath.value && fullPath.startsWith(rootPath.value)) {
    return fullPath.slice(rootPath.value.length);
  }
  return fullPath;
}

// ── Data loading ───────────────────────────────
async function loadProjects() {
  loading.value = true;
  try {
    const res = await scanApi.listProjects();
    projects.value = res.items;
    // If URL has ?project=<id>, pre-select it.
    const queryProject = route.query.project as string;
    if (queryProject) {
      projectId.value = queryProject;
    } else if (!projectId.value && projects.value.length > 0) {
      projectId.value = projects.value[0].id;
    }
    if (projectId.value) {
      await loadSource();
    }
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '加载项目列表失败');
  } finally {
    loading.value = false;
  }
}

async function onProjectChange() {
  source.value = null;
  files.value = [];
  fileCount.value = 0;
  rootPath.value = '';
  await loadSource();
}

async function loadSource() {
  if (!projectId.value) return;
  loading.value = true;
  try {
    const res = await scanApi.getProjectSource(projectId.value);
    if (res.source) {
      source.value = res.source;
      // Load file list for upload-type sources
      try {
        const list = await scanApi.listSourceFiles(res.source.id);
        files.value = list.files;
        fileCount.value = list.fileCount;
        rootPath.value = list.rootPath;
      } catch {
        // Not an upload-type source, or files not available
      }
    } else {
      source.value = null;
    }
  } catch {
    source.value = null;
  } finally {
    loading.value = false;
  }
}

// ── Upload ─────────────────────────────────────
async function onUpload(opts: any) {
  if (!projectId.value) {
    ElMessage.warning('请先选择项目');
    return;
  }
  const file: File = opts.file;
  if (file.size > 50 * 1024 * 1024) {
    ElMessage.error('文件过大 (>50MB)，请分批上传');
    return;
  }
  loading.value = true;
  try {
    const res = await scanApi.uploadSource(projectId.value, file);
    ElMessage.success(`上传成功！${res.upload.fileCount} 个文件已解压`);
    await loadSource();
  } catch (err: any) {
    const msg = err.response?.data?.error?.message ?? '上传失败';
    ElMessage.error(msg);
  } finally {
    loading.value = false;
  }
}

// ── Git connect (GitHub / GitLab) ──────────────
async function connectGit() {
  if (!projectId.value) {
    ElMessage.warning('请先选择项目');
    return;
  }
  if (!gitForm.repoUrl) {
    ElMessage.warning('请填写仓库 URL');
    return;
  }
  gitConnecting.value = true;
  try {
    const { data } = await apiClient.post('/provider/v1/scan/sources', {
      projectId: projectId.value,
      sourceType: gitForm.sourceType,
      repoUrl: gitForm.repoUrl,
      branch: gitForm.branch || 'main',
      accessToken: gitForm.accessToken || undefined,
    });
    ElMessage.success(`关联成功！${data.fileCount ?? '?'} 个文件已 clone`);
    showGithub.value = false;
    // Reset form
    gitForm.repoUrl = '';
    gitForm.accessToken = '';
    // Reload source info
    await loadSource();
  } catch (err: any) {
    const msg = err.response?.data?.error?.message ?? '关联失败';
    const detail = err.response?.data?.error?.details ?? '';
    ElMessage.error(`${msg}${detail ? ' — ' + detail.slice(0, 200) : ''}`);
  } finally {
    gitConnecting.value = false;
  }
}

async function onDeleteSource() {
  if (!source.value?.id) return;
  try {
    await ElMessageBox.confirm('删除此项目的源码关联？已上传的文件也会被清除。', '确认删除', { type: 'warning' });
    await scanApi.deleteSource(projectId.value);
    ElMessage.success('已删除');
    source.value = null;
    files.value = [];
    fileCount.value = 0;
  } catch {
    // cancelled
  }
}

// ── File preview ───────────────────────────────
async function preview(filePath: string) {
  if (!source.value?.id) return;
  previewPath.value = relativePath(filePath);
  try {
    const res = await scanApi.readSourceFile(source.value.id, filePath);
    previewContent.value = res.content ?? `(文件过大: ${res.size} bytes, 无法预览)`;
    previewOpen.value = true;
  } catch (err: any) {
    ElMessage.error('读取文件失败');
  }
}

// ── Actions ────────────────────────────────────

// Smart button: scan + deploy sandbox + auto-create PoC tasks
// for every open finding. The two "next-step" buttons are paired
// with this single entry point so the user doesn't have to click
// three separate places to close the loop.
async function onScan() {
  if (!projectId.value) return;
  scanning.value = true;
  try {
    const run = await scanApi.triggerScan({ projectId: projectId.value, triggerType: 'manual' });
    ElMessage.success(`扫描已触发 (ID: ${run.id.slice(0, 8)})，约 5 秒后完成`);
    // Auto-navigate to findings after a delay
    setTimeout(() => router.push(`/findings?project=${projectId.value}`), 3500);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '触发扫描失败');
  } finally {
    scanning.value = false;
  }
}

const deploying = ref(false);
const pocGenerating = ref(false);

// Resolves the project → customer → first active target. If
// there's no target the user must configure one before we can
// deploy the sandbox or run any PoC.
async function resolveTarget(): Promise<api.Target | null> {
  if (!projectId.value) return null;
  // 1. Get the project's customer_id
  const proj = await scanApi.getProject(projectId.value);
  const customerId = (proj as any).customer_id ?? (proj as any).customerId;
  if (!customerId) return null;
  // 2. List the customer's targets
  const { data } = await apiClient.get<{ items: api.Target[] }>(
    '/provider/v1/targets',
    { params: { customerId, status: 'active' } },
  );
  return data.items[0] ?? null;
}

// Two-step automation:
//   1. POST /targets/:id/deploy — build + run source as a sandbox
//   2. GET /findings?projectId — collect open findings
//      POST /validation/poc/generate × N — one PoC task per finding
async function onDeployAndVerify() {
  if (!projectId.value) return;
  deploying.value = true;
  let target: api.Target | null = null;
  try {
    target = await resolveTarget();
    if (!target) {
      ElMessage.warning('该项目还没有配置目标，请先去目标管理创建一个');
      router.push(`/targets?projectId=${projectId.value}`);
      return;
    }
    // 1. Deploy sandbox
    const depRes = await apiClient.post<any>(`/provider/v1/targets/${target.id}/deploy`);
    if (!depRes.data?.ok) {
      ElMessage.error(`部署失败: ${depRes.data?.error ?? 'unknown'}`);
      return;
    }
    ElMessage.success(`沙盒已启动 → ${depRes.data.sandboxUrl}`);
    deploying.value = false;

    // 2. Auto-generate PoC for every open finding
    pocGenerating.value = true;
    const findingsRes = await apiClient.get<{ items: any[]; total: number }>(
      '/provider/v1/findings', { params: { projectId: projectId.value } },
    );
    const openFindings = findingsRes.data.items.filter(
      (f) => f.status === 'open' || f.status === 'new',
    );
    if (openFindings.length === 0) {
      ElMessage.info('没有待验证的漏洞，请先触发白盒扫描');
      pocGenerating.value = false;
      router.push('/validation');
      return;
    }
    let successCount = 0;
    let failCount = 0;
    for (const f of openFindings) {
      try {
        await apiClient.post('/provider/v1/validation/poc/generate', {
          findingId: f.id, capability: 'poc_gen',
        });
        successCount++;
      } catch {
        failCount++;
      }
    }
    ElMessage.success(
      `已生成 ${successCount} 个 PoC 任务${failCount ? `, ${failCount} 个失败` : ''}`,
    );
    router.push('/validation');
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? err.message ?? '部署/PoC 失败');
  } finally {
    deploying.value = false;
    pocGenerating.value = false;
  }
}

// Watch for route query changes (e.g. navigated from customer detail with ?project=xxx)
watch(() => route.query.project, (val) => {
  if (val && val !== projectId.value) {
    projectId.value = val as string;
    onProjectChange();
  }
});

onMounted(loadProjects);
</script>

<style scoped>
.sources-page { display: flex; flex-direction: column; gap: 16px; padding: 24px; }
.page-header h2 { margin: 0 0 4px 0; }
.subtitle { color: var(--color-text-secondary); margin: 0; font-size: 13px; }

.project-card { }
.project-bar { display: flex; gap: 12px; align-items: center; }

.upload-card { text-align: center; padding: 24px 0; }
.upload-hint { padding: 32px 16px; text-align: center; }
.upload-title { font-size: 16px; font-weight: 500; margin: 12px 0 4px; }
.muted { color: var(--color-text-secondary); font-size: 12px; }
.form-hint { font-size: 11px; color: var(--color-text-placeholder); margin-top: 4px; line-height: 1.4; }
.github-zone { text-align: center; padding: 8px 0; }

.source-info { }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.source-meta { display: flex; gap: 12px; align-items: center; }
.meta-text { font-size: 13px; color: var(--color-text-secondary); }
.upload-mini { margin-bottom: 16px; }
.upload-hint-mini { display: flex; gap: 8px; align-items: center; padding: 8px; font-size: 13px; color: var(--color-text-secondary); }

.file-section { margin-top: 16px; }
.file-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }

.next-steps { }
.next-card { }
.next-header { display: flex; align-items: center; justify-content: space-between; }
.step-buttons { display: flex; gap: 16px; flex-wrap: wrap; }
.step-buttons .el-button { display: flex; flex-direction: column; align-items: flex-start; height: auto; padding: 12px 20px; }
.step-buttons .sub { display: block; font-size: 11px; opacity: 0.85; margin-top: 4px; font-weight: normal; }
.poc-progress { margin-top: 12px; }

.path { font-family: var(--font-mono); font-size: 12px; word-break: break-all; }
.preview-body {
  background: #f6f8fa; padding: 12px; max-height: 60vh; overflow: auto;
  font-size: 12px; font-family: var(--font-mono); white-space: pre-wrap;
  border-radius: 4px;
}
</style>
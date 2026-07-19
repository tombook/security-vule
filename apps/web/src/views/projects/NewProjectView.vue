<template>
  <div class="new-project-page">
    <el-card class="form-card" v-loading="loading">
      <template #header>
        <div class="card-header">
          <span>新建项目</span>
          <el-button @click="$router.back()">取消</el-button>
        </div>
      </template>

      <!-- ── 步骤指示器 ──────────────────────────────── -->
      <el-steps :active="step" finish-status="success" align-center class="steps">
        <el-step title="基本信息" description="客户 / 项目名" />
        <el-step title="源码采集" description="选择代码来源" />
        <el-step title="采集执行" description="上传或关联" />
      </el-steps>

      <!-- ── Step 1: 基本信息 ────────────────────────── -->
      <div v-show="step === 0" class="step-panel">
        <el-form :model="form" :rules="rules" ref="formRef" label-width="120">
          <el-form-item label="所属客户" prop="customerId">
            <el-select v-model="form.customerId" placeholder="选择客户" filterable style="width: 100%">
              <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
            </el-select>
          </el-form-item>
          <el-form-item label="项目名" prop="name">
            <el-input v-model="form.name" placeholder="如: web-checkout" maxlength="100" show-word-limit />
          </el-form-item>
          <el-form-item label="项目描述">
            <el-input v-model="form.description" type="textarea" :rows="2" placeholder="可选: 项目用途 / 技术栈 / 风险点" />
          </el-form-item>
          <el-form-item label="主分支" prop="defaultBranch">
            <el-input v-model="form.defaultBranch" placeholder="main" style="width: 200px" />
          </el-form-item>
        </el-form>
        <div class="step-actions">
          <el-button @click="$router.back()">取消</el-button>
          <el-button type="primary" @click="goStep2">下一步：选择源码采集方式</el-button>
        </div>
      </div>

      <!-- ── Step 2: 源码采集方式选择 ────────────────── -->
      <div v-show="step === 1" class="step-panel">
        <div class="source-options">
          <div
            v-for="opt in sourceOptions"
            :key="opt.key"
            class="source-option-card"
            :class="{ selected: selectedSource === opt.key }"
            @click="selectedSource = opt.key"
          >
            <el-icon :size="32" :color="selectedSource === opt.key ? 'var(--color-primary)' : 'var(--color-text-placeholder)'">
              <component :is="opt.icon" />
            </el-icon>
            <div class="opt-title">{{ opt.title }}</div>
            <div class="opt-desc muted">{{ opt.desc }}</div>
            <el-icon v-if="selectedSource === opt.key" class="check-icon" color="#10B981" :size="18">
              <CircleCheckFilled />
            </el-icon>
          </div>
        </div>

        <!-- 采集方式明细 -->
        <el-card v-if="selectedSource" shadow="never" class="detail-card">
          <template #header>
            <strong>{{ currentOption?.title }} — 详细配置</strong>
          </template>

          <!-- zip 上传明细 -->
          <div v-if="selectedSource === 'upload'">
            <el-upload
              drag
              :auto-upload="false"
              :on-change="onZipChange"
              :show-file-list="true"
              :limit="1"
              accept=".zip"
              :file-list="zipFileList"
            >
              <div class="upload-hint">
                <el-icon :size="40"><UploadFilled /></el-icon>
                <div>拖拽 zip 或点击选择</div>
                <div class="muted">支持 .zip 格式，最大 50MB</div>
              </div>
            </el-upload>
            <el-alert v-if="zipFile" type="success" :closable="false" show-icon class="mt">
              已选择: {{ zipFile.name }} ({{ (zipFile.size / 1024).toFixed(1) }} KB)
            </el-alert>
          </div>

          <!-- GitHub / GitLab 明细 -->
          <div v-else>
            <el-form label-width="100">
              <el-form-item label="仓库 URL" required>
                <el-input v-model="gitForm.repoUrl" :placeholder="selectedSource === 'github' ? 'https://github.com/org/repo.git' : 'https://gitlab.com/org/repo.git'" />
              </el-form-item>
              <el-form-item label="分支">
                <el-input v-model="gitForm.branch" placeholder="main" style="width: 200px" />
              </el-form-item>
              <el-form-item label="Access Token">
                <el-input v-model="gitForm.accessToken" type="password" show-password placeholder="ghp_... / glpat-... (私有仓库必填)" />
                <div class="form-hint muted">
                  Token 仅用于 git clone，加密存储。GitHub: Settings → Developer settings → Personal access tokens
                </div>
              </el-form-item>
            </el-form>
          </div>
        </el-card>

        <div class="step-actions">
          <el-button @click="step = 0">上一步</el-button>
          <el-button type="primary" @click="goStep3" :disabled="!canProceedStep3">
            {{ selectedSource === 'upload' ? '下一步：确认并创建' : '下一步：确认并创建' }}
          </el-button>
        </div>
      </div>

      <!-- ── Step 3: 确认并创建 ──────────────────────── -->
      <div v-show="step === 2" class="step-panel">
        <el-descriptions title="确认项目信息" :column="1" border>
          <el-descriptions-item label="所属客户">{{ getCustomerName(form.customerId) }}</el-descriptions-item>
          <el-descriptions-item label="项目名">{{ form.name }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ form.description || '—' }}</el-descriptions-item>
          <el-descriptions-item label="主分支">{{ form.defaultBranch }}</el-descriptions-item>
          <el-descriptions-item label="源码采集方式">
            <el-tag :type="selectedSource === 'upload' ? 'success' : 'info'">
              {{ currentOption?.title }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item v-if="selectedSource === 'upload' && zipFile" label="上传文件">
            {{ zipFile.name }} ({{ (zipFile.size / 1024).toFixed(1) }} KB)
          </el-descriptions-item>
          <el-descriptions-item v-if="selectedSource !== 'upload'" label="仓库 URL">
            {{ gitForm.repoUrl }}
          </el-descriptions-item>
          <el-descriptions-item v-if="selectedSource !== 'upload'" label="分支">
            {{ gitForm.branch || 'main' }}
          </el-descriptions-item>
          <el-descriptions-item v-if="selectedSource !== 'upload' && gitForm.accessToken" label="Token">
            ✅ 已提供 (加密存储)
          </el-descriptions-item>
        </el-descriptions>

        <el-alert type="info" :closable="false" show-icon class="mt">
          点击「创建项目」后将自动执行：创建项目 → 配置 → 采集源码 → 跳转代码源页面。
        </el-alert>

        <div class="step-actions">
          <el-button @click="step = 1">上一步</el-button>
          <el-button type="primary" size="large" :loading="loading" @click="onCreate">
            创建项目
          </el-button>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { ElMessage, type FormInstance, type FormRules, type UploadFile } from 'element-plus';
import {
  UploadFilled, CircleCheckFilled, Link, FolderOpened, Monitor,
} from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';
import * as scan from '@/api/scan';

const router = useRouter();
const route = useRoute();
const formRef = ref<FormInstance>();
const loading = ref(false);
const step = ref(0);
const customers = ref<any[]>([]);

// ── Form state ─────────────────────────────────
const form = reactive({
  customerId: '',
  name: '',
  description: '',
  defaultBranch: 'main',
});

const rules: FormRules = {
  customerId: [{ required: true, message: '请选择客户' }],
  name: [{ required: true, min: 1, max: 100, message: '请输入项目名' }],
  defaultBranch: [{ required: true, message: '请输入主分支' }],
};

// ── Source selection ───────────────────────────
const selectedSource = ref<'upload' | 'github' | 'gitlab'>('upload');
const sourceOptions = [
  { key: 'upload' as const, title: 'ZIP 上传', desc: '拖拽源码压缩包，适合本地代码 / 临时审计', icon: UploadFilled },
  { key: 'github' as const, title: 'GitHub 仓库', desc: '关联 GitHub 仓库（公开或私有），自动 clone', icon: Link },
  { key: 'gitlab' as const, title: 'GitLab 仓库', desc: '关联 GitLab 仓库（公开或私有），自动 clone', icon: FolderOpened },
];
const currentOption = computed(() => sourceOptions.find((o) => o.key === selectedSource.value));

// ── Upload (zip) state ─────────────────────────
const zipFile = ref<File | null>(null);
const zipFileList = ref<UploadFile[]>([]);

function onZipChange(file: UploadFile) {
  if (file.raw) {
    if (file.raw.size > 50 * 1024 * 1024) {
      ElMessage.error('文件超过 50MB，请压缩或分批上传');
      zipFileList.value = [];
      return;
    }
    zipFile.value = file.raw;
    zipFileList.value = [file];
  }
}

// ── Git form ───────────────────────────────────
const gitForm = reactive({
  repoUrl: '',
  branch: 'main',
  accessToken: '',
});

// ── Navigation guards ──────────────────────────
const canProceedStep3 = computed(() => {
  if (selectedSource.value === 'upload') return !!zipFile.value;
  return !!gitForm.repoUrl;
});

async function goStep2() {
  if (!formRef.value) return;
  const valid = await formRef.value.validate().catch(() => false);
  if (!valid) return;
  step.value = 1;
}

function goStep3() {
  if (!canProceedStep3.value) {
    ElMessage.warning(selectedSource.value === 'upload' ? '请先选择 zip 文件' : '请填写仓库 URL');
    return;
  }
  step.value = 2;
}

// ── Create + connect source ────────────────────
async function onCreate() {
  loading.value = true;
  try {
    // 1. Create project
    const project = await scan.createProject({
      customerId: form.customerId,
      name: form.name,
      description: form.description || undefined,
      defaultBranch: form.defaultBranch,
    });

    // 2. Configure (configuring → active)
    await apiClient.post(`/provider/v1/scan/projects/${project.id}/configure`);

    // 3. Connect source based on selection
    if (selectedSource.value === 'upload' && zipFile.value) {
      const res = await scan.uploadSource(project.id, zipFile.value, form.defaultBranch);
      ElMessage.success(`项目已创建，源码已上传（${res.upload.fileCount} 个文件）`);
    } else if (selectedSource.value === 'github' || selectedSource.value === 'gitlab') {
      const { data } = await apiClient.post('/provider/v1/scan/sources', {
        projectId: project.id,
        sourceType: selectedSource.value,
        repoUrl: gitForm.repoUrl,
        branch: gitForm.branch || form.defaultBranch,
        accessToken: gitForm.accessToken || undefined,
      });
      ElMessage.success(`项目已创建，${selectedSource.value === 'github' ? 'GitHub' : 'GitLab'} 源码已 clone（${data.fileCount ?? '?'} 个文件）`);
    } else {
      ElMessage.success(`项目「${project.name}」已创建`);
    }

    // 4. Navigate to sources page
    router.push(`/sources/manage?project=${project.id}`);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '创建失败');
  } finally {
    loading.value = false;
  }
}

// ── Helpers ────────────────────────────────────
function getCustomerName(id: string) {
  return customers.value.find((c) => c.id === id)?.name ?? '—';
}

async function fetchCustomers() {
  const { data } = await apiClient.get('/provider/v1/customers', { params: { size: 100 } });
  customers.value = data.items;
  const qCustomerId = route.query.customerId as string;
  if (qCustomerId) {
    form.customerId = qCustomerId;
  }
}

onMounted(fetchCustomers);
</script>

<style scoped>
.new-project-page { max-width: 760px; margin: 24px auto; }
.form-card { padding: 0; }
.card-header { display: flex; align-items: center; justify-content: space-between; }

.steps { margin-bottom: 32px; }

.step-panel { min-height: 300px; }

.step-actions {
  display: flex; justify-content: flex-end; gap: 12px;
  margin-top: 24px; padding-top: 16px;
  border-top: 1px solid var(--color-border-soft);
}

.source-options { display: flex; gap: 16px; margin-bottom: 20px; }
.source-option-card {
  flex: 1; min-width: 160px;
  display: flex; flex-direction: column; align-items: center;
  padding: 20px 12px; border-radius: 8px;
  border: 2px solid var(--color-border-soft);
  cursor: pointer; transition: all 0.2s;
  text-align: center; position: relative;
}
.source-option-card:hover { border-color: var(--color-primary); }
.source-option-card.selected {
  border-color: var(--color-primary);
  background: rgba(59, 130, 246, 0.06);
}
.opt-title { font-weight: 500; margin-top: 8px; font-size: 14px; }
.opt-desc { font-size: 11px; margin-top: 4px; line-height: 1.4; }
.check-icon { position: absolute; top: 8px; right: 8px; }

.detail-card { margin-top: 16px; }
.upload-hint { padding: 24px; text-align: center; }
.muted { color: var(--color-text-secondary); font-size: 12px; }
.form-hint { font-size: 11px; color: var(--color-text-placeholder); margin-top: 4px; line-height: 1.4; }
.mt { margin-top: 12px; }
</style>
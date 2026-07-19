<template>
  <div class="project-detail" v-loading="loading">
    <header class="page-header">
      <div>
        <h2>{{ project?.name ?? '项目详情' }}</h2>
        <p class="subtitle">
          客户: {{ project?.customer_name ?? '-' }} · 状态: {{ project?.status }} · SLA: {{ project?.sla_tier }}
        </p>
      </div>
      <div class="header-actions">
        <el-button @click="$router.back()">返回</el-button>
        <el-button type="primary" @click="onRunScan" :disabled="!project || project.status !== 'active'">
          立即扫描
        </el-button>
      </div>
    </header>

    <el-tabs v-model="activeTab" v-if="project">
      <el-tab-pane label="概览" name="overview">
        <el-row :gutter="16">
          <el-col :span="6">
            <el-card>
              <div class="stat-label">扫描数</div>
              <div class="stat-value">{{ project.recentScans?.length ?? 0 }}</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">开放漏洞</div>
              <div class="stat-value">
                {{ totalOpenFindings }}
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">活跃策略</div>
              <div class="stat-value-sm">{{ project.activePolicy?.name ?? '无' }}</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card>
              <div class="stat-label">数据保留</div>
              <div class="stat-value-sm">{{ project.data_retention_days }} 天</div>
            </el-card>
          </el-col>
        </el-row>

        <el-card class="mt">
          <template #header>漏洞严重度分布</template>
          <el-table :data="severityBreakdown" stripe>
            <el-table-column prop="severity" label="严重度" width="120">
              <template #default="{ row }">
                <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="120" />
            <el-table-column prop="count" label="数量" width="100" align="right" />
          </el-table>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="源配置" name="source">
        <el-card v-if="!project.source" class="empty-source">
          <el-empty description="尚未连接代码源">
            <el-button type="primary" @click="onConnectSource">连接 GitHub / GitLab / 上传</el-button>
          </el-empty>
        </el-card>
        <el-descriptions v-else :column="2" border>
          <el-descriptions-item label="类型">
            <el-tag>{{ project.source.source_type }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="仓库">{{ project.source.repo_full_name ?? '上传型' }}</el-descriptions-item>
          <el-descriptions-item label="主分支">{{ project.source.branch }}</el-descriptions-item>
          <el-descriptions-item label="Webhook ID">{{ project.source.webhook_id ?? '未注册' }}</el-descriptions-item>
          <el-descriptions-item label="最近同步">{{ project.source.last_synced_at ?? '未同步' }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="project.source.status === 'active' ? 'success' : 'warning'" size="small">
              {{ project.source.status }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="操作" :span="2">
            <el-button size="small" @click="onTestSource" :loading="testingSource">测试连接</el-button>
            <el-button size="small" type="danger" @click="onDisconnect">断开</el-button>
          </el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>

      <el-tab-pane label="扫描记录" name="scans">
        <el-table :data="project.recentScans" stripe>
          <el-table-column prop="id" label="ID" width="240" />
          <el-table-column prop="status" label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="scanStatusType(row.status)" size="small">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="trigger_type" label="触发" width="100" />
          <el-table-column label="开始" width="180">
            <template #default="{ row }">{{ row.started_at ?? '-' }}</template>
          </el-table-column>
          <el-table-column label="耗时" width="100">
            <template #default="{ row }">
              {{ row.duration_ms ? `${(row.duration_ms/1000).toFixed(1)}s` : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="发现" width="80" align="right">
            <template #default="{ row }">{{ row.findings_total }}</template>
          </el-table-column>
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button v-if="['queued','running'].includes(row.status)" link type="danger" size="small" @click="onCancelScan(row.id)">取消</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="Findings" name="findings">
        <el-empty description="Findings 列表(P2.1 待补)" />
      </el-tab-pane>

      <el-tab-pane label="PoC 验证" name="poc">
        <el-empty description="PoC 验证(P4.1 待补)" />
      </el-tab-pane>

      <el-tab-pane label="设置" name="settings">
        <el-form :model="editForm" label-width="140" style="max-width: 600px;">
          <el-form-item label="名称">
            <el-input v-model="editForm.name" />
          </el-form-item>
          <el-form-item label="描述">
            <el-input v-model="editForm.description" type="textarea" :rows="2" />
          </el-form-item>
          <el-form-item label="主分支">
            <el-input v-model="editForm.defaultBranch" />
          </el-form-item>
          <el-form-item label="SLA">
            <el-select v-model="editForm.slaTier">
              <el-option label="Standard" value="standard" />
              <el-option label="Priority" value="priority" />
              <el-option label="Premium" value="premium" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="onSaveSettings" :loading="saving">保存</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="showSourcePicker" title="连接代码源" width="500">
      <el-form label-width="100">
        <el-form-item label="提供商">
          <el-radio-group v-model="sourceProvider">
            <el-radio value="github">GitHub</el-radio>
            <el-radio value="gitlab">GitLab</el-radio>
            <el-radio value="upload">文件上传</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showSourcePicker = false">取消</el-button>
        <el-button type="primary" @click="onConfirmConnect" :loading="connecting">连接</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { apiClient } from '@/api/client';

const route = useRoute();
const router = useRouter();
const id = route.params.id as string;
const loading = ref(false);
const saving = ref(false);
const testingSource = ref(false);
const connecting = ref(false);
const project = ref<any>(null);
const activeTab = ref('overview');
const showSourcePicker = ref(false);
const sourceProvider = ref<'github' | 'gitlab' | 'upload'>('github');
const editForm = reactive({ name: '', description: '', defaultBranch: 'main', slaTier: 'standard' });

const totalOpenFindings = computed(() => {
  if (!project.value?.findingsBreakdown) return 0;
  return project.value.findingsBreakdown
    .filter((r: any) => !['fixed', 'false_positive', 'accepted_risk'].includes(r.status))
    .reduce((sum: number, r: any) => sum + r.count, 0);
});

const severityBreakdown = computed(() => {
  if (!project.value?.findingsBreakdown) return [];
  return project.value.findingsBreakdown;
});

function severityType(s: string) {
  return s === 'critical' ? 'danger' : s === 'high' ? 'warning' : s === 'medium' ? '' : 'info';
}

function scanStatusType(s: string) {
  return s === 'done' ? 'success' : s === 'failed' ? 'danger' : s === 'canceled' ? 'info' : 'warning';
}

async function fetchProject() {
  loading.value = true;
  try {
    const { data } = await apiClient.get(`/provider/v1/scan/projects/${id}`);
    project.value = data;
    editForm.name = data.name;
    editForm.description = data.description ?? '';
    editForm.defaultBranch = data.default_branch;
    editForm.slaTier = data.sla_tier;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '加载失败');
  } finally {
    loading.value = false;
  }
}

async function onSaveSettings() {
  saving.value = true;
  try {
    await apiClient.patch(`/provider/v1/scan/projects/${id}`, editForm);
    ElMessage.success('已保存');
    await fetchProject();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '保存失败');
  } finally {
    saving.value = false;
  }
}

async function onRunScan() {
  try {
    const { data } = await apiClient.post('/provider/v1/scan/scans/trigger', {
      projectId: id,
      triggerType: 'manual',
    });
    ElMessage.success(`扫描已触发: ${data.id}`);
    setTimeout(fetchProject, 500);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '触发失败');
  }
}

async function onCancelScan(scanId: string) {
  try {
    await apiClient.post(`/provider/v1/scan/scans/${scanId}/cancel`);
    ElMessage.success('已取消');
    await fetchProject();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '取消失败');
  }
}

function onConnectSource() {
  showSourcePicker.value = true;
}

async function onConfirmConnect() {
  if (sourceProvider.value === 'upload') {
    ElMessage.info('文件上传功能开发中');
    showSourcePicker.value = false;
    return;
  }
  connecting.value = true;
  try {
    const { data } = await apiClient.post('/provider/v1/oauth/connect/start', {
      provider: sourceProvider.value,
      projectId: id,
    });
    window.location.href = data.authorizeUrl;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '连接启动失败');
    connecting.value = false;
  }
}

async function onTestSource() {
  if (!project.value?.source?.id) return;
  testingSource.value = true;
  try {
    const { data } = await apiClient.post(`/provider/v1/oauth/sources/${project.value.source.id}/test`);
    ElMessage[data.ok ? 'success' : 'warning'](data.message);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '测试失败');
  } finally {
    testingSource.value = false;
  }
}

async function onDisconnect() {
  try {
    await ElMessageBox.confirm('确定断开代码源?会撤销 webhook 和停止同步。', '确认', { type: 'warning' });
  } catch { return; }
  try {
    await apiClient.delete(`/provider/v1/scan/projects/${id}/source`);
    ElMessage.success('已断开');
    await fetchProject();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '断开失败');
  }
}

onMounted(fetchProject);
</script>

<style scoped>
.project-detail { padding: 24px; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
.subtitle { color: var(--color-text-secondary); margin: 0; }
.header-actions { display: flex; gap: 8px; }
.stat-label { color: var(--color-text-secondary); font-size: 12px; margin-bottom: 8px; }
.stat-value { font-size: 32px; font-weight: 600; }
.stat-value-sm { font-size: 18px; font-weight: 500; }
.mt { margin-top: 16px; }
.empty-source { text-align: center; padding: 48px; }
</style>
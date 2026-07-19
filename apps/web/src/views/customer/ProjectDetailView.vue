<template>
  <div class="project-detail" v-loading="loading">
    <el-button link @click="goBack" class="back">
      <el-icon><ArrowLeft /></el-icon> 返回项目列表
    </el-button>

    <header class="page-header" v-if="project">
      <div class="header-row">
        <h2>{{ project.name }}</h2>
        <el-button type="primary" :icon="VideoPlay" :loading="triggering" @click="onRunScan">立即扫描</el-button>
      </div>
      <div class="meta">
        <el-tag>{{ project.status }}</el-tag>
        <el-tag type="info">{{ project.slaTier }} SLA</el-tag>
        <code v-if="project.defaultBranch">{{ project.defaultBranch }}</code>
        <span class="muted">数据保留 {{ project.dataRetentionDays }} 天</span>
      </div>
      <p v-if="project.description" class="description">{{ project.description }}</p>
    </header>

    <el-row :gutter="20" v-if="project">
      <el-col :span="8">
        <el-card>
          <div class="stat-label">总扫描数</div>
          <div class="stat-value">{{ project.totalScans }}</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="stat-label">总发现</div>
          <div class="stat-value">{{ project.totalFindings }}</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="stat-label">开放漏洞</div>
          <div class="stat-value" :class="project.openFindings > 0 ? 'text-high' : 'text-ok'">
            {{ project.openFindings }}
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card class="mt" v-if="activeScan">
      <template #header>
        <div class="card-header">
          <span><el-icon><Loading /></el-icon> 实时扫描进度</span>
          <el-tag :type="scanStatusColor(activeScan.status)">{{ scanStatusLabel(activeScan.status) }}</el-tag>
        </div>
      </template>
      <el-progress :percentage="scanProgress" :status="activeScan.status === 'failed' ? 'exception' : 'success'" />
      <p v-if="activeScan.status === 'running'" class="scan-tip">扫描进行中,完成后将自动刷新...</p>
    </el-card>

    <el-card class="mt">
      <template #header>扫描历史</template>
      <el-table :data="project?.scans ?? []" stripe>
        <el-table-column label="时间" width="180">
          <template #default="{ row }">
            {{ row.started_at ? formatTime(row.started_at) : '-' }}
          </template>
        </el-table-column>
        <el-table-column label="触发" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.trigger_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="scanStatusColor(row.status)">{{ scanStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="耗时" width="100">
          <template #default="{ row }">
            <span v-if="row.duration_ms">{{ Math.round(row.duration_ms / 1000) }}s</span>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
        <el-table-column label="总发现" prop="findings_total" width="100" align="right" />
        <el-table-column label="新发现" prop="findings_new" width="100" align="right" />
        <el-table-column label="已修复" prop="findings_fixed" width="100" align="right" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ArrowLeft, VideoPlay, Loading } from '@element-plus/icons-vue';
import { ElMessage } from 'element-plus';
import * as api from '@/api/customer';
import * as scan from '@/api/scan';

const route = useRoute();
const router = useRouter();
const project = ref<api.CustomerProjectDetail | null>(null);
const loading = ref(false);
const activeScan = ref<scan.ScanRun | null>(null);
const triggering = ref(false);
let pollTimer: number | undefined;

const scanProgress = computed(() => {
  if (!activeScan.value) return 0;
  if (activeScan.value.status === 'done') return 100;
  if (activeScan.value.status === 'failed') return 0;
  const elapsed = activeScan.value.startedAt ? (Date.now() - new Date(activeScan.value.startedAt).getTime()) : 0;
  return Math.min(95, Math.max(5, Math.round((elapsed / 10000) * 100)));
});

function scanStatusColor(s: string): '' | 'success' | 'warning' | 'info' | 'danger' {
  return ({ running: 'warning', queued: 'info', done: 'success', partial: 'warning', failed: 'danger', canceled: 'info' } as any)[s] ?? '';
}

function scanStatusLabel(s: string) {
  return ({ queued: '排队', running: '运行中', done: '完成', partial: '部分失败', failed: '失败', canceled: '已取消' } as Record<string, string>)[s] ?? s;
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function goBack() {
  router.push('/portal/projects');
}

async function fetch() {
  loading.value = true;
  try {
    project.value = await api.getProject(route.params.id as string);
  } finally { loading.value = false; }
}

async function onRunScan() {
  if (!project.value) return;
  triggering.value = true;
  try {
    const run = await scan.triggerScan({ projectId: project.value.id, triggerType: 'manual' });
    activeScan.value = run;
    ElMessage.success('扫描已启动,预计 3-10 秒完成');
    startPolling(run.id);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '启动扫描失败');
  } finally {
    triggering.value = false;
  }
}

function startPolling(scanId: string) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = window.setInterval(async () => {
    try {
      const s = await scan.getScan(scanId);
      activeScan.value = s;
      if (s.status === 'done' || s.status === 'failed' || s.status === 'canceled') {
        if (pollTimer) clearInterval(pollTimer);
        await fetch();
        ElMessage.success(`扫描完成:发现 ${s.findingsTotal} 个漏洞`);
      }
    } catch {}
  }, 2000);
}

onMounted(async () => {
  await fetch();
});
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<style scoped>
.project-detail { display: flex; flex-direction: column; gap: 16px; }
.back { padding: 0; }
.header-row { display: flex; align-items: center; justify-content: space-between; }
.page-header h2 { margin: 4px 0; font-size: 22px; }
.card-header { display: flex; align-items: center; gap: 12px; }
.scan-tip { color: var(--color-text-secondary); font-size: 12px; margin: 8px 0 0; }
.page-header .meta { display: flex; align-items: center; gap: 8px; }
.description { color: var(--color-text-secondary); font-size: 13px; margin: 8px 0 0; }
.stat-label { font-size: 12px; color: var(--color-text-secondary); }
.stat-value { font-size: 28px; font-weight: 700; margin-top: 8px; font-family: var(--font-mono); }
.text-high { color: #EF4444; }
.text-ok { color: #10B981; }
.mt { margin-top: 16px; }
.muted { color: var(--color-text-placeholder); }
</style>

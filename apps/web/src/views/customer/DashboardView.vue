<template>
  <div class="dashboard" v-loading="store.loading">
    <header class="page-header">
      <h2>{{ greeting }},{{ user?.full_name || user?.email }}</h2>
      <p class="subtitle">欢迎使用 security-vule · 您的安全态势一目了然</p>
    </header>

    <el-row :gutter="20" class="kpi-row">
      <el-col :xs="12" :sm="6">
        <el-card class="kpi critical" shadow="hover">
          <div class="kpi-label">紧急漏洞</div>
          <div class="kpi-value">{{ data?.kpis.criticalFindings ?? 0 }}</div>
          <div class="kpi-sub">CRITICAL 等级</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card class="kpi high" shadow="hover">
          <div class="kpi-label">高危漏洞</div>
          <div class="kpi-value">{{ data?.kpis.highFindings ?? 0 }}</div>
          <div class="kpi-sub">HIGH 等级</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card class="kpi proven" shadow="hover">
          <div class="kpi-label">已证可利用</div>
          <div class="kpi-value">{{ data?.kpis.confirmedExploits ?? 0 }}</div>
          <div class="kpi-sub">PoC 验证通过</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card class="kpi scans" shadow="hover">
          <div class="kpi-label">近 7 天扫描</div>
          <div class="kpi-value">{{ data?.kpis.recentScans ?? 0 }}</div>
          <div class="kpi-sub">扫描任务</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mt">
      <el-col :span="24">
        <el-card>
          <template #header>近期高危发现</template>
          <el-table :data="data?.recentFindings ?? []" stripe>
            <el-table-column label="严重度" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="severityColor(row.severity)">{{ row.severity }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="title" label="标题" min-width="240" />
            <el-table-column label="文件" min-width="280">
              <template #default="{ row }">
                <code class="file-cell">{{ row.filePath }}</code>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="最后发现" width="180">
              <template #default="{ row }">
                {{ formatTime(row.lastSeenAt) }}
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!data?.recentFindings?.length" description="近期待处理漏洞为空,继续保持 ✓" />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { storeToRefs } from 'pinia';
import { useAuthStore } from '@/stores/auth';
import * as api from '@/api/customer';

const auth = useAuthStore();
const { user } = storeToRefs(auth);

const data = ref<api.CustomerDashboard | null>(null);
const loading = ref(false);

const greeting = computed(() => {
  const h = new Date().getHours();
  if (h < 6) return '夜深了';
  if (h < 12) return '早上好';
  if (h < 18) return '下午好';
  return '晚上好';
});

function severityColor(s: string): '' | 'danger' | 'warning' | 'info' {
  if (s === 'critical') return 'danger';
  if (s === 'high') return 'warning';
  return 'info';
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

async function fetchData() {
  loading.value = true;
  try {
    data.value = await api.getDashboard();
  } finally { loading.value = false; }
}

onMounted(fetchData);
</script>

<style scoped>
.dashboard { display: flex; flex-direction: column; gap: 20px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.kpi-row { margin-bottom: 0; }
.kpi { text-align: center; }
.kpi-label { font-size: 12px; color: var(--color-text-secondary); }
.kpi-value { font-size: 32px; font-weight: 700; margin: 8px 0; font-family: var(--font-mono); }
.kpi-sub { font-size: 11px; color: var(--color-text-placeholder); }
.kpi.critical .kpi-value { color: #EF4444; }
.kpi.high .kpi-value { color: #F59E0B; }
.kpi.proven .kpi-value { color: #10B981; }
.kpi.scans .kpi-value { color: #4F46E5; }
.mt { margin-top: 20px; }
.file-cell { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-secondary); }
</style>

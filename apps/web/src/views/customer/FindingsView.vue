<template>
  <div class="findings-page" v-loading="loading">
    <header class="page-header">
      <h2>漏洞发现</h2>
      <p class="subtitle">本客户所有项目的漏洞</p>
    </header>

    <div class="toolbar">
      <el-select v-model="severity" placeholder="严重度" clearable style="width: 120px" @change="fetch">
        <el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="status" placeholder="状态" clearable style="width: 140px" @change="fetch">
        <el-option v-for="s in ['open','in_progress','confirmed','fixed','false_positive','closed']" :key="s" :label="s" :value="s" />
      </el-select>
    </div>

    <el-table :data="items" stripe @row-click="goDetail" style="cursor: pointer">
      <el-table-column label="严重度" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="severityColor(row.severity)">{{ row.severity }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="PoC 已证" width="90">
        <template #default="{ row }">
          <el-icon v-if="row.hasPocProof" color="#10B981" :size="20"><CircleCheckFilled /></el-icon>
          <el-icon v-else color="#9CA3AF" :size="20"><CircleClose /></el-icon>
        </template>
      </el-table-column>
      <el-table-column prop="title" label="标题" min-width="240" />
      <el-table-column label="CWE" width="100">
        <template #default="{ row }">
          <code v-for="c in row.cweIds" :key="c" class="cwe-tag">{{ c }}</code>
        </template>
      </el-table-column>
      <el-table-column prop="projectName" label="项目" min-width="160" />
      <el-table-column label="文件:行" min-width="220">
        <template #default="{ row }">
          <code class="file-cell">{{ row.filePath }}:{{ row.startLine }}</code>
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

    <el-empty v-if="!loading && items.length === 0" description="无匹配的漏洞" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { CircleCheckFilled, CircleClose } from '@element-plus/icons-vue';
import * as api from '@/api/customer';

const router = useRouter();
const items = ref<api.CustomerFinding[]>([]);
const severity = ref('');
const status = ref('');
const loading = ref(false);

function severityColor(s: string): '' | 'danger' | 'warning' | 'info' {
  if (s === 'critical') return 'danger';
  if (s === 'high') return 'warning';
  return 'info';
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function goDetail(row: api.CustomerFinding) {
  router.push(`/portal/findings/${row.id}`);
}

async function fetch() {
  loading.value = true;
  try {
    const res = await api.listFindings({ severity: severity.value || undefined, status: status.value || undefined });
    items.value = res.items;
  } finally { loading.value = false; }
}

onMounted(fetch);
</script>

<style scoped>
.findings-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.toolbar { display: flex; gap: 12px; }
.cwe-tag { background: #EEF2FF; color: #4F46E5; padding: 1px 5px; border-radius: 3px; font-size: 10px; margin-right: 4px; }
.file-cell { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-secondary); }
</style>

<template>
  <div class="reports-page" v-loading="loading">
    <header class="page-header">
      <h2>报告</h2>
      <p class="subtitle">本客户安全报告列表(周报/月报/合规)</p>
    </header>

    <el-table :data="items" stripe>
      <el-table-column label="类型" width="100">
        <template #default="{ row }">
          <el-tag size="small">{{ row.reportType }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="格式" width="80">
        <template #default="{ row }">
          <el-tag size="small" type="info">{{ row.format }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="账期" width="200">
        <template #default="{ row }">
          <span v-if="row.periodStart && row.periodEnd">
            {{ row.periodStart.slice(0, 10) }} ~ {{ row.periodEnd.slice(0, 10) }}
          </span>
          <span v-else class="muted">-</span>
        </template>
      </el-table-column>
      <el-table-column label="大小" width="100">
        <template #default="{ row }">
          <span v-if="row.fileSizeBytes">{{ formatBytes(Number(row.fileSizeBytes)) }}</span>
          <span v-else class="muted">-</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="row.status === 'ready' ? 'success' : 'info'">{{ row.status }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="生成时间" width="180">
        <template #default="{ row }">
          {{ formatTime(row.createdAt) }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" :disabled="row.status !== 'ready'" @click="onDownload">下载</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty v-if="!loading && items.length === 0" description="还没有报告" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import * as api from '@/api/customer';

const items = ref<api.CustomerReport[]>([]);
const loading = ref(false);

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function formatBytes(n: number) {
  if (n < 1024) return n + 'B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + 'KB';
  return (n / 1024 / 1024).toFixed(1) + 'MB';
}

function onDownload() {
  ElMessage.info('PDF 下载(Phase 3 上线 PDF 生成后生效)');
}

async function fetch() {
  loading.value = true;
  try {
    const res = await api.listReports();
    items.value = res.items;
  } finally { loading.value = false; }
}

onMounted(fetch);
</script>

<style scoped>
.reports-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.muted { color: var(--color-text-placeholder); }
</style>

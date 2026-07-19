<template>
  <div class="projects-page" v-loading="loading">
    <header class="page-header">
      <h2>项目</h2>
      <p class="subtitle">查看本客户接入的所有安全扫描项目</p>
    </header>

    <el-table :data="items" stripe>
      <el-table-column prop="name" label="项目名" min-width="200" />
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="statusColor(row.status)">{{ statusLabel(row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="slaTier" label="SLA" width="80" />
      <el-table-column prop="defaultBranch" label="主分支" width="120">
        <template #default="{ row }">
          <code v-if="row.defaultBranch">{{ row.defaultBranch }}</code>
          <span v-else class="muted">-</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描数" prop="totalScans" width="100" align="right" />
      <el-table-column label="开放漏洞" prop="openFindings" width="100" align="right">
        <template #default="{ row }">
          <span :class="row.openFindings > 0 ? 'text-high' : 'text-ok'">{{ row.openFindings }}</span>
        </template>
      </el-table-column>
      <el-table-column label="最近扫描" width="180">
        <template #default="{ row }">
          {{ row.lastScanAt ? formatTime(row.lastScanAt) : '从未' }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="100" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="goDetail(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty v-if="!loading && items.length === 0" description="还没有接入任何项目" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import * as api from '@/api/customer';

const router = useRouter();
const items = ref<api.CustomerProject[]>([]);
const loading = ref(false);

function statusColor(s: string): '' | 'success' | 'warning' | 'info' | 'danger' {
  return ({ active: 'success', configuring: 'info', paused: 'warning', error: 'danger' } as any)[s] ?? 'info';
}

function statusLabel(s: string) {
  return ({ active: '活跃', configuring: '配置中', paused: '暂停', error: '错误' } as Record<string, string>)[s] ?? s;
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function goDetail(row: api.CustomerProject) {
  router.push(`/portal/projects/${row.id}`);
}

async function fetch() {
  loading.value = true;
  try {
    const res = await api.listProjects();
    items.value = res.items;
  } finally { loading.value = false; }
}

onMounted(fetch);
</script>

<style scoped>
.projects-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.text-high { color: #EF4444; font-weight: 600; }
.text-ok { color: #10B981; }
.muted { color: var(--color-text-placeholder); }
</style>

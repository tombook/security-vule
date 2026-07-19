<template>
  <div class="usage-page" v-loading="loading">
    <header class="page-header">
      <h2>用量</h2>
      <p class="subtitle">透明化:本客户的 AI token 消耗(无隐藏扣费)</p>
    </header>

    <el-row :gutter="20">
      <el-col :span="8">
        <el-card>
          <div class="stat-label">本月事件数</div>
          <div class="stat-value">{{ data?.totals.eventCount ?? 0 }}</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="stat-label">本月总 tokens</div>
          <div class="stat-value">{{ (data?.totals.totalTokens ?? 0).toLocaleString() }}</div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <div class="stat-label">本月成本(USD)</div>
          <div class="stat-value">${{ (data?.totals.totalCost ?? 0).toFixed(4) }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mt">
      <el-col :span="12">
        <el-card>
          <template #header>按能力分解</template>
          <el-table :data="data?.byCapability ?? []" stripe>
            <el-table-column prop="capability" label="能力" />
            <el-table-column label="tokens" align="right">
              <template #default="{ row }">{{ row.tokens.toLocaleString() }}</template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!data?.byCapability?.length" description="无用量" :image-size="60" />
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>近 30 天趋势</template>
          <el-table :data="data?.byDay ?? []" stripe max-height="320">
            <el-table-column label="日期" width="120">
              <template #default="{ row }">{{ row.day }}</template>
            </el-table-column>
            <el-table-column label="tokens" align="right">
              <template #default="{ row }">{{ row.tokens.toLocaleString() }}</template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!data?.byDay?.length" description="无近期用量" :image-size="60" />
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="data?.quota" class="mt">
      <template #header>当前套餐</template>
      <el-descriptions :column="3" border>
        <el-descriptions-item label="套餐"><el-tag>{{ data.quota.plan }}</el-tag></el-descriptions-item>
        <el-descriptions-item label="月度配额">{{ data.quota.monthlyTokenQuota.toLocaleString() }} tokens</el-descriptions-item>
        <el-descriptions-item label="账户余额">${{ data.quota.balanceUsd.toFixed(2) }}</el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import * as api from '@/api/customer';

const data = ref<api.CustomerUsage | null>(null);
const loading = ref(false);

async function fetch() {
  loading.value = true;
  try {
    data.value = await api.getUsage();
  } finally { loading.value = false; }
}

onMounted(fetch);
</script>

<style scoped>
.usage-page { display: flex; flex-direction: column; gap: 20px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.stat-label { font-size: 12px; color: var(--color-text-secondary); }
.stat-value { font-size: 28px; font-weight: 700; margin-top: 8px; font-family: var(--font-mono); }
.mt { margin-top: 20px; }
</style>

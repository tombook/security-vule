<template>
  <div class="kpi-card" :class="`kpi-${kpi.key}`">
    <div class="kpi-label">{{ kpi.label }}</div>
    <div class="kpi-value">
      <span class="value">{{ formatValue(kpi.value) }}</span>
      <span v-if="kpi.unit" class="unit">{{ kpi.unit }}</span>
    </div>
    <div v-if="kpi.secondary || kpi.change || kpi.badge" class="kpi-meta">
      <span v-if="kpi.secondary">{{ kpi.secondary }}</span>
      <span v-else-if="kpi.change">{{ kpi.change }}</span>
      <span v-else-if="kpi.badge">{{ kpi.badge }}</span>
    </div>
    <el-button v-if="kpi.action" type="primary" link size="small" @click="goAction">
      查看详情 →
    </el-button>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import type { KpiItem } from '@/api/workbench';

const props = defineProps<{ kpi: KpiItem }>();
const router = useRouter();

function formatValue(v: number | string) {
  if (typeof v === 'number') {
    return v >= 10000 ? (v / 1000).toFixed(1) + 'K' : v.toLocaleString();
  }
  return v;
}

function goAction() {
  if (props.kpi.action) {
    ElMessage.info('Phase 2 上线:' + props.kpi.action);
  }
}
</script>

<style scoped>
.kpi-card {
  background: var(--color-bg-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  padding: 20px;
  display: flex; flex-direction: column; gap: 8px;
  min-height: 130px;
  transition: box-shadow 0.2s;
}
.kpi-card:hover { box-shadow: var(--shadow-md); }
.kpi-label { color: var(--color-text-secondary); font-size: 13px; }
.kpi-value { display: flex; align-items: baseline; gap: 4px; }
.kpi-value .value {
  font-family: var(--font-mono);
  font-size: 28px; font-weight: 600;
  color: var(--color-text-primary);
}
.kpi-value .unit { font-size: 13px; color: var(--color-text-secondary); }
.kpi-meta { font-size: 12px; color: var(--color-text-secondary); }
.kpi-critical_findings .value { color: var(--color-high); }
</style>

<template>
  <div class="workbench">
    <div class="welcome">
      <h2>欢迎回来,{{ auth.user?.full_name || '管理员' }} · 本租户:演示安全服务商</h2>
    </div>
    <div class="kpi-grid" v-loading="loading">
      <KpiCard v-for="kpi in kpis" :key="kpi.key" :kpi="kpi" />
    </div>
    <el-row :gutter="24" class="bottom-grid">
      <el-col :span="12">
        <el-card>
          <template #header>最近活动</template>
          <el-empty v-if="!activity.length" description="还没有活动,接入第一个客户开始" />
          <el-timeline v-else>
            <el-timeline-item v-for="(item, i) in activity" :key="i" :timestamp="item.time">
              {{ item.text }}
            </el-timeline-item>
          </el-timeline>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>Top 5 高危客户</template>
          <el-empty v-if="!topCustomers.length" description="暂无数据" />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { ElMessage } from 'element-plus';
import KpiCard from '@/components/KpiCard.vue';
import { getOverview, type KpiItem } from '@/api/workbench';
import { useAuthStore } from '@/stores/auth';

const auth = useAuthStore();
const loading = ref(false);
const kpis = ref<KpiItem[]>([]);
const topCustomers = ref<any[]>([]);
const activity = ref<{ time: string; text: string }[]>([]);
let timer: number | undefined;

async function fetchOverview() {
  loading.value = true;
  try {
    const data = await getOverview();
    kpis.value = data.kpis;
    topCustomers.value = data.top_customers;
  } catch (err: any) {
    // 静默失败,axios 拦截器已 Toast
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchOverview();
  timer = window.setInterval(fetchOverview, 60_000);  // 60s 自动刷新
});
onUnmounted(() => { if (timer) clearInterval(timer); });
</script>

<style scoped>
.workbench { display: flex; flex-direction: column; gap: 24px; }
.welcome h2 { margin: 0; font-size: 18px; font-weight: 600; color: var(--color-text-primary); }
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
.bottom-grid { margin-top: 8px; }
@media (max-width: 1200px) {
  .kpi-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>

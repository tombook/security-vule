<template>
  <div class="success-page">
    <el-result icon="success" title="支付成功!" sub-title="您的订阅已激活">
      <template #extra>
        <el-button type="primary" @click="$router.push('/billing')">返回计费</el-button>
        <el-button @click="$router.push('/')">回工作台</el-button>
      </template>
    </el-result>
    <el-card class="info-card">
      <h3 style="margin: 0 0 12px;">订阅已更新</h3>
      <p>您的账户状态已通过 Stripe webhook 自动更新。新套餐的额度与功能已立即生效。</p>
      <el-alert type="success" :closable="false" show-icon>
        <strong>Mock 模式:</strong> 真实环境由 Stripe Webhook 异步通知后端。本次模拟直接调用 mock-confirm 触发同样的 webhook 事件。
      </el-alert>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { getSubscription, type SubscriptionStatus } from '@/api/stripe';

const sub = ref<SubscriptionStatus['subscription']>(null);

onMounted(async () => {
  try {
    const res = await getSubscription();
    sub.value = res.subscription;
  } catch {}
});
</script>

<style scoped>
.success-page { max-width: 720px; margin: 40px auto; }
.info-card { margin-top: 24px; }
.info-card p { color: var(--color-text-secondary); line-height: 1.6; }
</style>

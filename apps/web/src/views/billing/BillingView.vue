<template>
  <div class="billing-page" v-loading="loading">
    <header class="page-header">
      <div>
        <h2>计费</h2>
        <p class="subtitle">套餐 · 用量账单 · 配额 · 发票 · 成本分摊</p>
      </div>
      <div class="header-actions">
        <el-tag v-if="subscription" :type="subscription.status === 'active' ? 'success' : 'warning'" size="large">
          {{ subscription.plan?.toUpperCase() }} · {{ subscription.status }}
        </el-tag>
        <el-button :icon="Setting" @click="onManageBilling">Manage Billing</el-button>
      </div>
    </header>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="套餐" name="plans">
        <el-row :gutter="16">
          <el-col v-for="p in plans" :key="p.id" :xs="24" :sm="12" :md="8">
            <el-card class="plan-card" :class="{ recommended: p.code === 'pro', current: p.code === currentPlan }" shadow="hover">
              <div v-if="p.code === 'pro'" class="ribbon">推荐</div>
              <div v-if="p.code === currentPlan" class="ribbon current-ribbon">当前</div>
              <div class="plan-header">
                <span class="plan-name">{{ p.displayName }}</span>
                <span class="plan-code">{{ p.code }}</span>
              </div>
              <div class="plan-price">
                <span class="currency">$</span>
                <span class="amount">{{ p.priceUsd }}</span>
                <span class="period">/ {{ p.billingPeriod === 'monthly' ? '月' : p.billingPeriod === 'yearly' ? '年' : '季' }}</span>
              </div>
              <p class="plan-desc">{{ p.description }}</p>
              <el-divider />
              <ul class="feature-list">
                <li><el-icon color="#10B981"><Check /></el-icon> {{ p.monthlyTokenQuota?.toLocaleString() ?? '∞' }} tokens / 月</li>
                <li><el-icon color="#10B981"><Check /></el-icon> 最多 {{ p.monthlyCustomerLimit ?? '∞' }} 客户</li>
                <li><el-icon color="#10B981"><Check /></el-icon> 最多 {{ p.monthlyProjectLimit ?? '∞' }} 项目</li>
                <li v-if="p.features?.poc_library"><el-icon color="#10B981"><Check /></el-icon> PoC 库</li>
                <li v-if="p.features?.white_label"><el-icon color="#10B981"><Check /></el-icon> 白标</li>
                <li v-if="p.features?.sso"><el-icon color="#10B981"><Check /></el-icon> SSO</li>
              </ul>
              <el-button
                :type="p.code === 'pro' ? 'primary' : 'default'"
                class="plan-btn"
                :disabled="p.code === currentPlan"
                @click="onUpgrade(p.code)"
              >
                {{ p.code === currentPlan ? '当前套餐' : p.code === 'enterprise' ? '联系销售' : '升级到此' }}
              </el-button>
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <el-tab-pane label="用量账单" name="quota">
        <el-row :gutter="16">
          <el-col :span="8">
            <el-card>
              <div class="quota-label">当前套餐</div>
              <div class="quota-value">{{ quota?.currentPlan?.plan ?? '-' }}</div>
              <div class="quota-sub">月配额 {{ quota?.currentPlan?.monthlyTokenQuota?.toLocaleString() ?? '-' }} tokens</div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card>
              <div class="quota-label">本月已用</div>
              <div class="quota-value text-highlight">{{ quota?.usageThisMonth?.total?.toLocaleString() ?? 0 }}</div>
              <div class="quota-sub">tokens / 总计</div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card>
              <div class="quota-label">账户余额</div>
              <div class="quota-value">${{ quota?.currentPlan?.balanceUsd?.toFixed(2) ?? '0.00' }}</div>
              <div class="quota-sub">USD</div>
            </el-card>
          </el-col>
        </el-row>

        <el-card class="mt">
          <template #header>按能力分解</template>
          <el-table :data="capabilityRows" stripe>
            <el-table-column prop="capability" label="能力" />
            <el-table-column label="本月用量 (tokens)">
              <template #default="{ row }">{{ row.tokens.toLocaleString() }}</template>
            </el-table-column>
          </el-table>
        </el-card>

        <el-card v-if="quota?.recentAlerts?.length" class="mt">
          <template #header>近期配额预警</template>
          <el-alert
            v-for="a in quota.recentAlerts" :key="a.level + a.capability"
            :type="alertType(a.level)" :title="`${a.level} - ${a.capability}`"
            :description="`已用 ${a.used.toLocaleString()} / 上限 ${a.limit.toLocaleString()}`"
            show-icon class="mb"
          />
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="`发票 (${invoices.length})`" name="invoices">
        <el-table :data="invoices" stripe>
          <el-table-column prop="invoiceNumber" label="发票号" width="180" />
          <el-table-column label="账期" width="200">
            <template #default="{ row }">
              <span v-if="row.periodStart && row.periodEnd">
                {{ row.periodStart.slice(0, 10) }} ~ {{ row.periodEnd.slice(0, 10) }}
              </span>
              <span v-else class="muted">-</span>
            </template>
          </el-table-column>
          <el-table-column label="合计" width="120" align="right">
            <strong>${{ row.totalUsd.toFixed(2) }}</strong>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="invoiceStatusColor(row.status)" size="small">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="付款时间" width="180">
            <template #default="{ row }">
              {{ row.paidAt ? formatTime(row.paidAt) : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="操作" width="100" fixed="right">
            <template #default><el-button link type="primary" size="small" @click="onDownload">下载</el-button></template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="成本分摊" name="allocation">
          <el-table :data="allocations" stripe>
            <el-table-column prop="customerId" label="客户 ID" width="280" />
            <el-table-column label="策略" width="140">
              <template #default="{ row }"><el-tag size="small">{{ row.strategy }}</el-tag></template>
            </el-table-column>
            <el-table-column label="固定金额" width="120" align="right">
              <template #default="{ row }">
                <span v-if="row.flatAmountUsd">${{ row.flatAmountUsd.toFixed(2) }}</span>
                <span v-else class="muted">-</span>
              </template>
            </el-table-column>
            <el-table-column label="乘数" prop="customMultiplier" width="100" />
            <el-table-column label="生效" width="200">
              <template #default="{ row }">
                {{ row.effectiveFrom }}<span v-if="row.effectiveTo"> ~ {{ row.effectiveTo }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="showCheckout" title="模拟 Stripe 结账" width="600">
      <el-alert v-if="checkoutResult" type="info" :closable="false" show-icon class="mb">
        <strong>Mock 模式:</strong> 真实 Stripe 会跳转到 checkout.stripe.com
      </el-alert>
      <div v-if="checkoutResult" class="checkout-card">
        <div class="checkout-row">
          <span class="label">会话 ID:</span>
          <code>{{ checkoutResult.checkoutId }}</code>
        </div>
        <div class="checkout-row">
          <span class="label">回调 URL:</span>
          <code class="url">{{ checkoutResult.url }}</code>
        </div>
        <div class="checkout-row">
          <span class="label">签名:</span>
          <code>{{ checkoutResult.signature }}</code>
        </div>
      </div>
      <template #footer>
        <el-button @click="showCheckout = false">取消</el-button>
        <el-button type="primary" @click="onConfirmPayment">模拟支付成功</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Check, Setting } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';
import * as stripe from '@/api/stripe';

const router = useRouter();
const activeTab = ref('plans');
const plans = ref<any[]>([]);
const quota = ref<any>(null);
const invoices = ref<any[]>([]);
const allocations = ref<any[]>([]);
const loading = ref(false);
const subscription = ref<stripe.SubscriptionStatus['subscription']>(null);
const showCheckout = ref(false);
const checkoutResult = ref<stripe.CheckoutResult | null>(null);

const currentPlan = computed(() => subscription.value?.plan ?? quota.value?.currentPlan?.plan ?? 'pro');
const frontendUrl = window.location.origin;

const capabilityRows = computed(() => {
  if (!quota.value?.usageThisMonth?.byCapability) return [];
  return Object.entries(quota.value.usageThisMonth.byCapability).map(([capability, tokens]) => ({
    capability, tokens: Number(tokens),
  }));
});

function alertType(level: string): 'warning' | 'error' | 'info' {
  if (level.includes('90') || level.includes('95')) return 'error';
  if (level.includes('80')) return 'warning';
  return 'info';
}

function invoiceStatusColor(s: string): 'success' | 'warning' | 'danger' | 'info' {
  return ({ paid: 'success', issued: 'warning', overdue: 'danger', draft: 'info', void: 'info' } as any)[s] ?? 'info';
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

async function onUpgrade(plan: string) {
  if (plan === 'enterprise') {
    ElMessage.info('请联系销售: enterprise@security-vule.com');
    return;
  }
  try {
    const res = await stripe.createCheckout(plan, `${frontendUrl}/billing/success`, `${frontendUrl}/billing`);
    checkoutResult.value = res;
    showCheckout.value = true;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '创建结账失败');
  }
}

async function onConfirmPayment() {
  if (!checkoutResult.value) return;
  try {
    const tenantId = JSON.parse(atob(localStorage.getItem('access_token')?.split('.')[1] ?? 'e30=')).tenant_id;
    const plan = JSON.parse(atob(localStorage.getItem('access_token')?.split('.')[1] ?? 'e30=')).plan;
    const res = await stripe.mockConfirm(checkoutResult.value.checkoutId, tenantId, currentPlan.value);
    if (res.ok) {
      ElMessage.success('支付成功!订阅已更新');
      showCheckout.value = false;
      router.push('/billing/success');
    }
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '确认支付失败');
  }
}

async function onManageBilling() {
  try {
    const { url } = await stripe.getPortalUrl(`${frontendUrl}/billing`);
    window.location.href = url;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '打开客户门户失败');
  }
}

function onDownload() {
  ElMessage.info('PDF 下载(Phase 3 上线 PDF 生成后生效)');
}

async function fetchAll() {
  loading.value = true;
  try {
    const [p, q, i, a, sub] = await Promise.all([
      apiClient.get('/provider/v1/billing/plans'),
      apiClient.get('/provider/v1/billing/quota'),
      apiClient.get('/provider/v1/billing/stripe/invoices'),
      apiClient.get('/provider/v1/billing/allocation'),
      stripe.getSubscription(),
    ]);
    plans.value = p.data.items;
    quota.value = q.data;
    invoices.value = i.data.items;
    allocations.value = a.data.items;
    subscription.value = sub.subscription;
  } finally { loading.value = false; }
}

onMounted(fetchAll);
</script>

<style scoped>
.billing-page { display: flex; flex-direction: column; gap: 16px; }
.page-header { display: flex; align-items: flex-start; justify-content: space-between; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.header-actions { display: flex; align-items: center; gap: 12px; }
.plan-card { position: relative; margin-bottom: 16px; height: 100%; }
.plan-card.recommended { border: 2px solid #4F46E5; }
.plan-card.current { border: 2px solid #10B981; background: #f0fdf4; }
.ribbon { position: absolute; top: 12px; right: -6px; background: #4F46E5; color: #fff; padding: 2px 8px; font-size: 11px; border-radius: 3px; }
.current-ribbon { background: #10B981; top: 12px; right: -6px; }
.plan-header { display: flex; align-items: baseline; gap: 8px; }
.plan-name { font-size: 16px; font-weight: 600; }
.plan-code { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-secondary); }
.plan-price { display: flex; align-items: baseline; margin: 12px 0 8px; }
.plan-price .currency { font-size: 16px; color: var(--color-text-secondary); }
.plan-price .amount { font-size: 32px; font-weight: 700; margin: 0 4px; }
.plan-price .period { color: var(--color-text-secondary); }
.plan-desc { color: var(--color-text-secondary); font-size: 12px; min-height: 32px; }
.feature-list { list-style: none; padding: 0; margin: 0 0 16px; font-size: 13px; }
.feature-list li { display: flex; align-items: center; gap: 6px; padding: 4px 0; }
.plan-btn { width: 100%; }
.quota-label { font-size: 12px; color: var(--color-text-secondary); margin-bottom: 8px; }
.quota-value { font-size: 28px; font-weight: 600; }
.quota-value.text-highlight { color: #4F46E5; }
.quota-sub { font-size: 12px; color: var(--color-text-secondary); margin-top: 4px; }
.mb { margin-bottom: 8px; }
.mt { margin-top: 16px; }
.muted { color: var(--color-text-placeholder); }
.checkout-card { background: #f9fafb; padding: 16px; border-radius: 6px; margin-top: 12px; }
.checkout-row { display: flex; gap: 8px; padding: 4px 0; align-items: baseline; }
.checkout-row .label { width: 80px; color: var(--color-text-secondary); font-size: 12px; }
.checkout-row code { font-size: 11px; font-family: var(--font-mono); }
.checkout-row .url { word-break: break-all; }
</style>

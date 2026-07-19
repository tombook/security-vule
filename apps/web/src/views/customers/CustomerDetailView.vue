<template>
  <div class="customer-detail">
    <header class="page-header" v-loading="loading">
      <div>
        <h2>{{ customer?.name ?? '客户详情' }}</h2>
        <p class="subtitle">SLA: {{ customer?.sla_tier }} · 状态: {{ customer?.status }}</p>
      </div>
      <div class="header-actions">
        <el-button @click="$router.back()">返回</el-button>
        <el-button type="primary" @click="onNewProject">新建项目</el-button>
      </div>
    </header>

    <!-- ── 安全评估向导卡片 ────────────────────────────
         一个 5 步引导面板，按项目的实际状态展示每步是否
         完成。点击卡片直接跳转到对应页面。 -->
    <el-card class="wizard-card" v-if="projects.length > 0" shadow="never">
      <template #header>
        <strong>安全评估流程</strong>
        <span class="muted" style="margin-left: 8px">端到端：源码上传 → 白盒检测 → Docker 部署 → PoC 验证</span>
      </template>
      <div class="wizard-steps">
        <div
          v-for="step in wizardSteps"
          :key="step.key"
          class="wizard-step"
          :class="{ done: step.done, active: !step.done && step.active }"
          @click="step.action"
        >
          <div class="step-icon">
            <el-icon v-if="step.done" color="#10B981" :size="20"><CircleCheckFilled /></el-icon>
            <el-icon v-else-if="step.active" color="#3B82F6" :size="20"><Loading /></el-icon>
            <el-icon v-else :size="20" color="var(--color-text-placeholder)"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/></svg></el-icon>
          </div>
          <div class="step-body">
            <div class="step-title">{{ step.title }}</div>
            <div class="step-desc muted">{{ step.desc }}</div>
          </div>
        </div>
      </div>
    </el-card>

    <el-tabs v-model="activeTab" v-if="customer">
      <el-tab-pane label="项目" name="projects">
        <el-table :data="projects" stripe @row-click="(row: any) => openProjectDrawer(row)">
          <el-table-column prop="name" label="名称" min-width="160">
            <template #default="{ row }">
              <el-link type="primary" @click.stop="openProjectDrawer(row)">{{ row.name }}</el-link>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="statusColor(row.status)" size="small">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="sla_tier" label="SLA" width="80" />
          <el-table-column label="源码" width="120">
            <template #default="{ row }">
              <el-tag v-if="row.source_type" :type="row.source_type === 'upload' ? 'success' : 'info'" size="small">
                {{ sourceLabel(row.source_type) }}
              </el-tag>
              <span v-else class="muted">未配置</span>
            </template>
          </el-table-column>
          <el-table-column label="扫描" width="60" align="right">
            <template #default="{ row }">{{ row.scan_count }}</template>
          </el-table-column>
          <el-table-column label="开放漏洞" width="80" align="right">
            <template #default="{ row }">
              <el-tag v-if="row.open_findings > 0" type="danger" size="small">{{ row.open_findings }}</el-tag>
              <span v-else class="muted">0</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="220" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click.stop="$router.push(`/sources/manage?project=${row.id}`)">源码</el-button>
              <el-button link type="primary" size="small" @click.stop="triggerScan(row.id)">扫描</el-button>
              <el-button link type="primary" size="small" @click.stop="$router.push(`/findings?project=${row.id}`)">漏洞</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="联系人" name="contacts">
        <el-button type="primary" @click="showAddContact = true">+ 新增联系人</el-button>
        <el-table :data="contacts" stripe class="mt">
          <el-table-column prop="name" label="姓名" />
          <el-table-column prop="email" label="邮箱" />
          <el-table-column prop="role" label="角色" width="100">
            <template #default="{ row }">
              <el-tag size="small">{{ row.role }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="主联系人" width="100">
            <template #default="{ row }">
              <el-icon v-if="row.is_primary" color="#10B981"><Check /></el-icon>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="计费" name="billing">
        <el-descriptions v-if="customer.billing" :column="2" border>
          <el-descriptions-item label="套餐">{{ customer.billing.plan }}</el-descriptions-item>
          <el-descriptions-item label="状态">{{ customer.billing.status }}</el-descriptions-item>
          <el-descriptions-item label="月配额">{{ customer.billing.monthly_token_quota?.toLocaleString() }} tokens</el-descriptions-item>
          <el-descriptions-item label="账户余额">${{ customer.billing.balance_usd ?? '0.00' }}</el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>

      <el-tab-pane label="白标" name="whitelabel">
        <el-empty description="白标配置请到 [设置 → 白标]" />
      </el-tab-pane>
    </el-tabs>

    <!-- ── 项目详情抽屉 ──────────────────────────────── -->
    <el-drawer
      v-model="drawerOpen"
      :title="`项目详情: ${drawerProject?.name ?? ''}`"
      direction="rtl"
      size="600"
      :destroy-on-close="true"
    >
      <div v-loading="drawerLoading">
        <!-- 基本信息 -->
        <el-descriptions title="基本信息" :column="2" border size="small">
          <el-descriptions-item label="状态">
            <el-tag :type="statusColor(drawerProject?.status)" size="small">{{ drawerProject?.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="SLA">{{ drawerProject?.sla_tier }}</el-descriptions-item>
          <el-descriptions-item label="主分支">{{ drawerProject?.default_branch }}</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ formatDate(drawerProject?.created_at) }}</el-descriptions-item>
          <el-descriptions-item label="描述" :span="2">{{ drawerProject?.description || '—' }}</el-descriptions-item>
        </el-descriptions>

        <!-- 源码采集信息 -->
        <el-descriptions title="源码采集" :column="1" border size="small" class="mt">
          <el-descriptions-item label="采集方式">
            <template v-if="drawerDetail?.source">
              <el-tag :type="drawerDetail.source.source_type === 'upload' ? 'success' : 'info'" size="small">
                {{ sourceLabel(drawerDetail.source.source_type) }}
              </el-tag>
            </template>
            <span v-else class="muted">未配置源码</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="drawerDetail?.source" label="分支">
            {{ drawerDetail.source.branch }}
          </el-descriptions-item>
          <el-descriptions-item v-if="drawerDetail?.source?.repo_url" label="仓库 URL">
            <code class="mono">{{ drawerDetail.source.repo_url }}</code>
          </el-descriptions-item>
          <el-descriptions-item v-if="drawerDetail?.source?.status" label="源码状态">
            <el-tag :type="drawerDetail.source.status === 'active' ? 'success' : 'warning'" size="small">
              {{ drawerDetail.source.status }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item v-if="drawerDetail?.source?.last_synced_at" label="最后同步">
            {{ formatDate(drawerDetail.source.last_synced_at) }}
          </el-descriptions-item>
        </el-descriptions>

        <!-- 漏洞统计 -->
        <div v-if="drawerDetail?.findingsBreakdown?.length" class="mt">
          <strong>漏洞分布</strong>
          <div class="breakdown-bar">
            <span
              v-for="fb in drawerDetail.findingsBreakdown"
              :key="fb.severity"
              class="breakdown-item"
            >
              <el-tag :type="severityColor(fb.severity)" size="small">{{ fb.severity }}</el-tag>
              <span class="count">{{ fb.count }}</span>
              <span v-if="fb.status" class="muted">({{ fb.status }})</span>
            </span>
          </div>
        </div>

        <!-- 最近扫描 -->
        <div v-if="drawerDetail?.recentScans?.length" class="mt">
          <strong>最近扫描</strong>
          <el-table :data="drawerDetail.recentScans" stripe size="small" class="mt">
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="scanStatusColor(row.status)" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="trigger_type" label="触发" width="80" />
            <el-table-column prop="findings_total" label="漏洞" width="60" align="right" />
            <el-table-column label="时间" width="120">
              <template #default="{ row }">{{ formatDate(row.finished_at || row.started_at) }}</template>
            </el-table-column>
          </el-table>
        </div>

        <!-- 操作按钮 -->
        <div class="drawer-actions mt">
          <el-button type="primary" @click="$router.push(`/sources/manage?project=${drawerProject?.id}`)">管理源码</el-button>
          <el-button @click="triggerScan(drawerProject?.id); drawerOpen = false">触发扫描</el-button>
          <el-button @click="$router.push(`/findings?project=${drawerProject?.id}`)">查看漏洞</el-button>
          <el-button @click="$router.push(`/targets`)">配置目标</el-button>
        </div>
      </div>
    </el-drawer>

    <el-dialog v-model="showAddContact" title="新增联系人" width="500">
      <el-form :model="newContact" label-width="100">
        <el-form-item label="姓名"><el-input v-model="newContact.name" /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="newContact.email" type="email" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="newContact.role">
            <el-option label="主联系人" value="primary" />
            <el-option label="安全对接" value="security" />
            <el-option label="财务" value="billing" />
            <el-option label="工程" value="engineering" />
            <el-option label="其他" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item label="主联系人"><el-switch v-model="newContact.isPrimary" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddContact = false">取消</el-button>
        <el-button type="primary" @click="onAddContact" :loading="addingContact">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { Check, CircleCheckFilled, Loading } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';

const route = useRoute();
const router = useRouter();
const id = route.params.id as string;
const loading = ref(false);
const customer = ref<any>(null);
const projects = ref<any[]>([]);
const contacts = ref<any[]>([]);
const activeTab = ref('projects');
const showAddContact = ref(false);
const addingContact = ref(false);
const newContact = reactive({ name: '', email: '', role: 'other', isPrimary: false });
const scanning = ref(false);

// ── 项目详情 Drawer ─────────────────────────────
const drawerOpen = ref(false);
const drawerLoading = ref(false);
const drawerProject = ref<any>(null);
const drawerDetail = ref<any>(null);

async function openProjectDrawer(row: any) {
  drawerProject.value = row;
  drawerOpen.value = true;
  drawerLoading.value = true;
  drawerDetail.value = null;
  try {
    const { data } = await apiClient.get(`/provider/v1/scan/projects/${row.id}`);
    drawerDetail.value = data;
  } catch {
    // detail load failed — still show basic info from row
  } finally {
    drawerLoading.value = false;
  }
}

function sourceLabel(type: string) {
  if (type === 'upload') return 'ZIP 上传';
  if (type === 'github') return 'GitHub';
  if (type === 'gitlab') return 'GitLab';
  return type;
}

function severityColor(s: string) {
  return s === 'critical' ? 'danger' : s === 'high' ? 'danger' : s === 'medium' ? 'warning' : 'info';
}

function scanStatusColor(s: string) {
  return s === 'done' ? 'success' : s === 'running' ? 'warning' : s === 'failed' ? 'danger' : 'info';
}

function formatDate(s?: string) {
  if (!s) return '—';
  const d = new Date(s);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// ── 安全评估向导状态 ────────────────────────────────
// 5 步引导：源码上传 → 白盒检测 → Docker 部署 → PoC 验证 → 报告
// 每步根据第一个项目的实际状态判断 done/active/locked。
const firstProject = computed(() => projects.value[0] ?? null);

const wizardSteps = computed(() => {
  const p = firstProject.value;
  return [
    {
      key: 'source',
      title: '1. 上传源码',
      desc: p?.scan_count > 0 || p?.open_findings > 0
        ? '✅ 源码已上传' : '上传 zip 或关联 GitHub',
      done: p?.scan_count > 0 || p?.open_findings > 0,
      active: !p?.scan_count,
      action: () => p && router.push(`/sources/manage?project=${p.id}`),
    },
    {
      key: 'detect',
      title: '2. 白盒检测',
      desc: p?.scan_count > 0
        ? `✅ 已完成 ${p.scan_count} 次扫描` : '触发 AST 级安全扫描',
      done: p?.scan_count > 0,
      active: p?.scan_count === 0,
      action: () => p && triggerScan(p.id),
    },
    {
      key: 'findings',
      title: '3. 查看漏洞',
      desc: p?.open_findings > 0
        ? `⚠️ ${p.open_findings} 个开放漏洞` : '等待扫描完成',
      done: false,
      active: p?.scan_count > 0,
      action: () => p && router.push(`/findings?project=${p.id}`),
    },
    {
      key: 'target',
      title: '4. 部署目标',
      desc: '部署 Docker 运行环境',
      done: false,
      active: p?.open_findings > 0,
      action: () => router.push('/targets'),
    },
    {
      key: 'poc',
      title: '5. PoC 验证',
      desc: '验证漏洞可利用性',
      done: false,
      active: p?.open_findings > 0,
      action: () => router.push('/validation'),
    },
  ];
});

function statusColor(s: string) {
  return s === 'active' ? 'success' : s === 'configuring' ? 'warning' : 'info';
}

async function fetchAll() {
  loading.value = true;
  try {
    const [c, p] = await Promise.all([
      apiClient.get(`/provider/v1/customers/${id}`),
      apiClient.get(`/provider/v1/scan/projects`, { params: { customerId: id } }),
    ]);
    customer.value = c.data;
    projects.value = p.data.items;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '加载失败');
  } finally {
    loading.value = false;
  }
}

async function fetchContacts() {
  if (activeTab.value !== 'contacts') return;
  const { data } = await apiClient.get(`/provider/v1/customers/${id}/contacts`).catch(() => ({ data: [] }));
  contacts.value = data;
}

async function onAddContact() {
  if (!newContact.name || !newContact.email) {
    ElMessage.warning('请填写姓名和邮箱');
    return;
  }
  addingContact.value = true;
  try {
    await apiClient.post(`/provider/v1/customers/${id}/contacts`, newContact);
    ElMessage.success('联系人已添加');
    showAddContact.value = false;
    Object.assign(newContact, { name: '', email: '', role: 'other', isPrimary: false });
    await fetchContacts();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '添加失败');
  } finally {
    addingContact.value = false;
  }
}

function onNewProject() {
  router.push({ path: '/projects/new', query: { customerId: id } });
}

async function triggerScan(projectId: string) {
  scanning.value = true;
  try {
    await apiClient.post('/provider/v1/scan/scans/trigger', {
      projectId, triggerType: 'manual',
    });
    ElMessage.success('扫描已触发，约 5 秒后完成。完成后跳转漏洞列表');
    setTimeout(() => {
      router.push(`/findings?project=${projectId}`);
    }, 3000);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '触发失败，请先上传源码');
  } finally {
    scanning.value = false;
  }
}

watch(activeTab, fetchContacts);
onMounted(fetchAll);
</script>

<style scoped>
.customer-detail { padding: 24px; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
.subtitle { color: var(--color-text-secondary); margin: 0; }
.header-actions { display: flex; gap: 8px; }
.mt { margin-top: 16px; }
.muted { color: var(--color-text-secondary); font-size: 12px; }
.mono { font-family: var(--font-mono); font-size: 12px; word-break: break-all; }
.mt { margin-top: 16px; }

.breakdown-bar { display: flex; gap: 16px; margin-top: 8px; flex-wrap: wrap; }
.breakdown-item { display: flex; align-items: center; gap: 4px; }
.breakdown-item .count { font-weight: 600; font-size: 14px; margin-left: 4px; }
.drawer-actions { display: flex; gap: 8px; flex-wrap: wrap; padding-top: 16px; border-top: 1px solid var(--color-border-soft); }

.wizard-card { margin-bottom: 16px; }
.wizard-steps { display: flex; gap: 16px; flex-wrap: wrap; }
.wizard-step {
  flex: 1;
  min-width: 160px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px;
  border-radius: 8px;
  border: 1px solid var(--color-border-soft);
  cursor: pointer;
  transition: all 0.2s;
}
.wizard-step:hover { border-color: var(--color-primary); background: var(--color-bg-2); }
.wizard-step.done { border-color: #10B981; background: rgba(16, 185, 129, 0.06); }
.wizard-step.active { border-color: #3B82F6; background: rgba(59, 130, 246, 0.06); }
.step-icon { flex-shrink: 0; }
.step-title { font-weight: 500; font-size: 13px; }
.step-desc { font-size: 11px; margin-top: 2px; }
</style>
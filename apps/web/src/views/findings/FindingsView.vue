<template>
  <div class="findings-page" v-loading="loading">
    <header class="page-header">
      <div>
        <h2>{{ filters.projectId ? '漏洞明细' : '漏洞总览' }}</h2>
        <p class="subtitle">
          <template v-if="filters.projectId">
            共 {{ total }} 个 · 已选 {{ selected.length }}
            <el-tag size="small" type="info" effect="plain" style="margin-left: 8px">
              项目过滤: {{ filters.projectId.slice(0, 8) }}…
            </el-tag>
            <el-button link size="small" @click="clearProjectFilter">清除筛选</el-button>
          </template>
          <template v-else>
            {{ summary.length }} 个项目有漏洞，共 {{ grandTotal }} 个漏洞 ·
            {{ grandOpen }} 个待处理 ·
            {{ grandCritical }} 个严重
          </template>
        </p>
      </div>
      <div class="header-actions">
        <el-button
          v-if="filters.projectId"
          :disabled="!selected.length"
          @click="showBulkDialog = true"
        >批量 Triage</el-button>
      </div>
    </header>

    <!-- ─────────  汇总视图 (无 projectId)  ───────── -->
    <template v-if="!filters.projectId">
      <div class="summary-stats">
        <div class="stat-card stat-danger" @click="filterSeverity('critical')">
          <div class="stat-num">{{ grandCritical }}</div>
          <div class="stat-label">严重 (Critical)</div>
        </div>
        <div class="stat-card stat-warning" @click="filterSeverity('high')">
          <div class="stat-num">{{ grandHigh }}</div>
          <div class="stat-label">高危 (High)</div>
        </div>
        <div class="stat-card stat-info" @click="filterSeverity('medium')">
          <div class="stat-num">{{ grandMedium }}</div>
          <div class="stat-label">中危 (Medium)</div>
        </div>
        <div class="stat-card stat-low" @click="filterSeverity('low')">
          <div class="stat-num">{{ grandLow }}</div>
          <div class="stat-label">低危 (Low)</div>
        </div>
      </div>

      <el-table
        :data="summary" stripe
        @row-click="goProjectDetail"
        class="summary-table"
      >
        <el-table-column prop="customer_name" label="客户" min-width="160">
          <template #default="{ row }">
            <el-link type="primary" @click.stop="filterCustomer(row.customer_id)">
              {{ row.customer_name }}
            </el-link>
          </template>
        </el-table-column>
        <el-table-column prop="project_name" label="项目" min-width="180">
          <template #default="{ row }">
            <el-link type="primary" @click.stop="goProjectDetail(row)">
              {{ row.project_name }}
            </el-link>
            <el-tag size="small" :type="projectStatusType(row.project_status)" effect="plain" style="margin-left: 6px">
              {{ row.project_status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="漏洞总数" width="100" align="right" sortable :sort-by="(r) => r.total">
          <template #default="{ row }">
            <strong :class="row.total > 0 ? 'has-findings' : 'muted'">{{ row.total }}</strong>
          </template>
        </el-table-column>
        <el-table-column label="待处理" width="90" align="right">
          <template #default="{ row }">
            <el-tag v-if="row.open_count > 0" type="warning" size="small">{{ row.open_count }}</el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="严重度分布" min-width="240">
          <template #default="{ row }">
            <div class="sev-bar">
              <el-tag v-if="row.critical" type="danger" size="small">C {{ row.critical }}</el-tag>
              <el-tag v-if="row.high" type="danger" size="small" effect="plain">H {{ row.high }}</el-tag>
              <el-tag v-if="row.medium" type="warning" size="small" effect="plain">M {{ row.medium }}</el-tag>
              <el-tag v-if="row.low" type="info" size="small" effect="plain">L {{ row.low }}</el-tag>
              <span v-if="!row.critical && !row.high && !row.medium && !row.low" class="muted">—</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="PoC 验证" width="120" align="right">
          <template #default="{ row }">
            <span v-if="row.poc_total > 0">
              <strong :class="row.poc_proven > 0 ? 'proven' : 'muted'">
                {{ row.poc_proven }} / {{ row.poc_total }}
              </strong>
              <span class="muted" style="margin-left: 4px">已证</span>
            </span>
            <span v-else class="muted">未开始</span>
          </template>
        </el-table-column>
        <el-table-column label="最近发现" width="140">
          <template #default="{ row }">{{ formatTime(row.last_finding_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="goProjectDetail(row)">查看明细</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && summary.length === 0" description="当前租户暂无漏洞数据" />
    </template>

    <!-- ─────────  明细视图 (?project=xxx)  ───────── -->
    <template v-else>
      <el-row :gutter="12" class="filters">
        <el-col :span="6">
          <el-select v-model="filters.customerId" placeholder="所有客户" clearable @change="fetchList">
            <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="filters.severity" placeholder="严重度" clearable @change="fetchList">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="filters.status" placeholder="状态" clearable @change="fetchList">
            <el-option label="Open" value="open" />
            <el-option label="In Progress" value="in_progress" />
            <el-option label="Fixed" value="fixed" />
            <el-option label="Escalated" value="escalated" />
            <el-option label="False Positive" value="false_positive" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-input v-model="filters.q" placeholder="搜索 标题 / 文件" clearable @input="onSearchInput">
            <template #prefix><el-icon><Search /></el-icon></template>
          </el-input>
        </el-col>
      </el-row>

      <el-table
        :data="items" stripe
        @selection-change="onSelectionChange"
        @row-click="(row) => $router.push(`/findings/${row.id}`)"
        row-key="id"
      >
        <el-table-column type="selection" width="48" />
        <el-table-column prop="title" label="标题" min-width="200">
          <template #default="{ row }">
            <el-link type="primary" @click.stop="$router.push(`/findings/${row.id}`)">{{ row.title }}</el-link>
            <div class="row-sub">
              <el-tag v-if="row.exploit_proven" type="danger" size="small">PoC 已证</el-tag>
              <span class="file">{{ row.file_path }}:{{ row.start_line }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="严重度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="检测引擎" width="180">
          <template #default="{ row }">
            <el-tag v-for="e in (row.engines || [])" :key="e" size="small" :type="engineType(e)" effect="plain" style="margin-right: 4px">
              {{ engineLabel(e) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="customer_name" label="客户" width="120" />
        <el-table-column prop="project_name" label="项目" width="120" />
        <el-table-column label="PoC" width="60" align="right">
          <template #default="{ row }">
            <span v-if="row.poc_run_count > 0">{{ row.poc_run_count }}</span>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
        <el-table-column label="最近" width="120">
          <template #default="{ row }">{{ formatTime(row.last_seen_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="runPoc(row)" :loading="runningPocId === row.id">运行 PoC</el-button>
            <el-button link type="primary" size="small" @click.stop="$router.push(`/validation?finding=${row.id}`)" v-if="row.poc_run_count > 0">查看</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="page" v-model:page-size="size" :total="total"
        :page-sizes="[20, 50, 100]" layout="total, sizes, prev, pager, next" @current-change="fetchList" @size-change="fetchList"
        class="pagination"
      />
    </template>

    <el-dialog v-model="showBulkDialog" title="批量 Triage" width="500">
      <el-form label-width="100">
        <el-form-item label="操作">
          <el-select v-model="bulkAction">
            <el-option label="标记为处理中" value="triage" />
            <el-option label="标记为误报" value="false_positive" />
            <el-option label="标记为接受风险" value="accepted_risk" />
            <el-option label="升级给客户" value="escalate" />
          </el-select>
        </el-form-item>
        <el-form-item label="原因">
          <el-input v-model="bulkReason" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showBulkDialog = false">取消</el-button>
        <el-button type="primary" @click="onBulkSubmit" :loading="bulkSubmitting">确认</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { Search } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';

const loading = ref(false);
const items = ref<any[]>([]);
const total = ref(0);
const customers = ref<any[]>([]);
const page = ref(1);
const size = ref(20);
const selected = ref<any[]>([]);
const showBulkDialog = ref(false);
const bulkAction = ref('triage');
const bulkReason = ref('');
const bulkSubmitting = ref(false);
const filters = reactive({ customerId: '', severity: '', status: '', q: '', projectId: '' });
const summary = ref<any[]>([]);

const grandTotal = computed(() => summary.value.reduce((a, b) => a + (b.total ?? 0), 0));
const grandOpen = computed(() => summary.value.reduce((a, b) => a + (b.open_count ?? 0), 0));
const grandCritical = computed(() => summary.value.reduce((a, b) => a + (b.critical ?? 0), 0));
const grandHigh = computed(() => summary.value.reduce((a, b) => a + (b.high ?? 0), 0));
const grandMedium = computed(() => summary.value.reduce((a, b) => a + (b.medium ?? 0), 0));
const grandLow = computed(() => summary.value.reduce((a, b) => a + (b.low ?? 0), 0));

const route = useRoute();

// Sync route query (?project=xxx) into the filters and refetch
// when the URL changes (e.g. customer detail drawer → click
// '查看漏洞'). Also re-read on mount.
function syncProjectFromQuery() {
  const q = route.query.project;
  if (typeof q === 'string' && q) {
    if (filters.projectId !== q) {
      filters.projectId = q;
      page.value = 1;
      fetchList();
    }
  } else if (filters.projectId) {
    filters.projectId = '';
    page.value = 1;
    fetchList();
  } else {
    // Initial load on the summary view — fetch the roll-up.
    fetchSummary();
  }
}
watch(() => route.query.project, syncProjectFromQuery);
syncProjectFromQuery();

const summaryLoading = ref(false);

async function fetchSummary() {
  summaryLoading.value = true;
  try {
    const params: any = {};
    if (filters.customerId) params.customerId = filters.customerId;
    const { data } = await apiClient.get<{ items: any[] }>('/provider/v1/findings/summary', { params });
    summary.value = data.items ?? [];
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '加载汇总失败');
    summary.value = [];
  } finally {
    summaryLoading.value = false;
  }
}

function goProjectDetail(row: any) {
  // Row click on the summary view drills into the per-project
  // detail list — equivalent to navigating to ?project=<id>.
  const { project: _drop, ...rest } = route.query;
  void _drop;
  router.replace({ query: rest });
  filters.projectId = row.project_id;
  page.value = 1;
  fetchList();
}

function filterCustomer(customerId: string) {
  // When in summary view, click on a customer name to re-query
  // summary scoped to that customer.
  filters.customerId = customerId;
  fetchSummary();
}

function filterSeverity(_sev: string) {
  // Quick drill-down from a stat card: switches to the detail
  // view of all open findings across the tenant with that severity.
  // (Not strictly per-project, but the stat cards live on the
  // roll-up and this is the cheapest cross-project triage.)
  filters.customerId = '';
  filters.severity = _sev;
  filters.status = 'open';
  fetchList();
}

function projectStatusType(s: string) {
  return s === 'active' ? 'success' : s === 'paused' ? 'warning' : 'info';
}

// Strip ?project= from the URL and reset the filter — used by
// the "清除筛选" button next to the active project tag.
const router = useRouter();
function clearProjectFilter() {
  filters.projectId = '';
  const { project: _drop, ...rest } = route.query;
  void _drop;
  router.replace({ query: rest });
  page.value = 1;
  fetchList();
}

// 引擎标签映射
function engineLabel(e: string): string {
  const map: Record<string, string> = {
    'mock-scanner': '正则',
    'ast-engine': 'AST污点',
    'semgrep': 'Semgrep',
    'trivy': 'Trivy',
    'llm': 'LLM',
    'poc': 'PoC',
  };
  return map[e] || e;
}
function engineType(e: string): 'primary' | 'success' | 'warning' | 'info' | 'danger' {
  const map: Record<string, any> = {
    'mock-scanner': 'info',
    'ast-engine': 'success',
    'semgrep': 'warning',
    'trivy': 'warning',
    'llm': 'primary',
    'poc': 'danger',
  };
  return map[e] || 'info';
}

function severityType(s: string) {
  return s === 'critical' ? 'danger' : s === 'high' ? 'warning' : s === 'medium' ? '' : 'info';
}
function statusType(s: string) {
  return s === 'open' ? 'danger' : s === 'in_progress' ? 'warning' : s === 'fixed' ? 'success' : 'info';
}
function formatTime(t: string | null) {
  if (!t) return '-';
  const d = new Date(t);
  return `${d.getMonth() + 1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
}

let searchTimer: any;
function onSearchInput() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(fetchList, 300);
}

async function fetchCustomers() {
  try {
    const { data } = await apiClient.get('/provider/v1/customers', { params: { size: 100 } });
    customers.value = data.items;
  } catch {}
}

async function fetchList() {
  loading.value = true;
  try {
    const params: any = { page: page.value, size: size.value };
    if (filters.customerId) params.customerId = filters.customerId;
    if (filters.projectId) params.projectId = filters.projectId;
    if (filters.severity) params.severity = filters.severity;
    if (filters.status) params.status = filters.status;
    if (filters.q) params.q = filters.q;
    const { data } = await apiClient.get('/provider/v1/findings', { params });
    items.value = data.items;
    total.value = data.total;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '加载失败');
  } finally {
    loading.value = false;
  }
}

const runningPocId = ref<string | null>(null);
async function runPoc(row: any) {
  runningPocId.value = row.id;
  try {
    // Generate → approve → execute in one go so the operator
    // doesn't have to walk three dialogs per finding. The backend
    // already enforces the workflow; we just collapse the steps.
    const gen = await apiClient.post('/provider/v1/validation/poc/generate',
      { findingId: row.id, capability: 'poc_gen' });
    const pocId = gen.data.id;
    await apiClient.post(`/provider/v1/validation/poc/${pocId}/approve`, {});
    const exec = await apiClient.post(`/provider/v1/validation/poc/${pocId}/execute`);
    if (exec.data.exploitProven) {
      ElMessage.success(`漏洞已证实 · HTTP ${exec.data.httpStatus} · target ${(exec.data.targetId || '').slice(0,8)}`);
    } else {
      ElMessage.warning(`未证实漏洞 · ${exec.data.evidenceSummary || 'verifier 返回 false'}`);
    }
    await fetchList();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? err.message ?? 'PoC 执行失败');
  } finally {
    runningPocId.value = null;
  }
}

function onSelectionChange(rows: any[]) {
  selected.value = rows;
}

async function onBulkSubmit() {
  if (!selected.value.length) return;
  bulkSubmitting.value = true;
  try {
    const { data } = await apiClient.post('/provider/v1/findings/bulk', {
      ids: selected.value.map((f) => f.id),
      action: bulkAction.value,
      reason: bulkReason.value || undefined,
    });
    ElMessage.success(`已更新 ${data.updated} 条漏洞 → ${data.targetStatus}`);
    showBulkDialog.value = false;
    selected.value = [];
    await fetchList();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '批量操作失败');
  } finally {
    bulkSubmitting.value = false;
  }
}

onMounted(async () => {
  await fetchCustomers();
  await fetchList();
});
</script>

<style scoped>
.findings-page { padding: 24px; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.subtitle { color: var(--color-text-secondary); margin: 0; }
.muted { color: var(--color-text-secondary); }
.has-findings { color: var(--color-warning); }
.proven { color: var(--color-danger); font-weight: 600; }

.summary-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
.stat-card {
  padding: 16px; border-radius: 8px;
  background: var(--color-bg-card);
  border: 1px solid var(--color-border-soft);
  cursor: pointer; transition: all 0.2s;
}
.stat-card:hover { border-color: var(--color-primary); transform: translateY(-1px); }
.stat-num { font-size: 28px; font-weight: 700; line-height: 1.2; }
.stat-label { font-size: 12px; color: var(--color-text-secondary); margin-top: 4px; }
.stat-card.stat-danger .stat-num { color: var(--color-danger); }
.stat-card.stat-warning .stat-num { color: var(--color-warning); }
.stat-card.stat-info .stat-num { color: var(--color-info); }
.stat-card.stat-low .stat-num { color: var(--color-text-secondary); }

.summary-table { cursor: pointer; }
.sev-bar { display: flex; gap: 4px; flex-wrap: wrap; }

.filters { margin-bottom: 12px; }
.pagination { justify-content: flex-end; display: flex; margin-top: 16px; }
.row-sub { margin-top: 4px; display: flex; gap: 6px; align-items: center; }
.row-sub .file { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-secondary); }
.header-actions { display: flex; gap: 8px; }
.filters { margin-bottom: 16px; }
.row-sub { font-size: 12px; color: var(--color-text-secondary); margin-top: 4px; display: flex; align-items: center; gap: 8px; }
.file { font-family: var(--font-mono); }
.muted { color: var(--color-text-secondary); }
.pagination { margin-top: 16px; justify-content: flex-end; display: flex; }
</style>
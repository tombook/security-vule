<template>
  <div class="sources-page" v-loading="loading">
    <header class="page-header">
      <h2>代码源汇总</h2>
      <p class="subtitle">
        租户项目代码资产 · 共 {{ rows.length }} 个项目 ·
        <span class="has-source">{{ withSourceCount }} 已配置源码</span> ·
        <span class="no-source">{{ withoutSourceCount }} 待配置</span>
      </p>
    </header>

    <el-card>
      <div class="toolbar">
        <el-input v-model="q" placeholder="搜索项目名 / 租户" clearable style="width: 260px" @input="onSearchInput">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="customerFilter" placeholder="按租户过滤" clearable style="width: 200px" @change="load">
          <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
        </el-select>
        <el-select v-model="statusFilter" placeholder="状态" clearable style="width: 130px" @change="load">
          <el-option label="configuring" value="configuring" />
          <el-option label="active" value="active" />
          <el-option label="paused" value="paused" />
        </el-select>
        <el-button :icon="Refresh" @click="load">刷新</el-button>
        <div style="flex: 1" />
        <el-button type="primary" :icon="Plus" @click="openCreate">+ 新建项目</el-button>
      </div>

      <el-table :data="filteredRows" stripe @row-click="goManage">
        <el-table-column label="租户" prop="customer_name" min-width="140">
          <template #default="{ row }">
            <el-link type="primary" @click.stop="$router.push(`/customers/${row.customer_id}`)">
              {{ row.customer_name }}
            </el-link>
          </template>
        </el-table-column>
        <el-table-column label="项目" prop="name" min-width="160">
          <template #default="{ row }">
            <el-link type="primary" @click.stop="goManage(row)">
              {{ row.name }}
            </el-link>
            <code class="slug" v-if="row.slug">{{ row.slug }}</code>
          </template>
        </el-table-column>
        <el-table-column label="状态" prop="status" width="120">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="SLA" prop="sla_tier" width="80">
          <template #default="{ row }">
            {{ customerSla(row.customer_id) }}
          </template>
        </el-table-column>
        <el-table-column label="主分支" prop="default_branch" width="100" />
        <el-table-column label="源码" width="160">
          <template #default="{ row }">
            <template v-if="row.source">
              <el-tag :type="sourceTypeColor(row.source.source_type)" size="small" effect="plain">
                {{ sourceLabel(row.source.source_type) }}
              </el-tag>
              <span v-if="row.source.branch" class="muted" style="margin-left: 6px">{{ row.source.branch }}</span>
            </template>
            <span v-else class="muted">未配置</span>
          </template>
        </el-table-column>
        <el-table-column label="文件" prop="source_file_count" width="80" align="right">
          <template #default="{ row }">
            <span v-if="row.source?.file_count" class="strong">{{ row.source.file_count }}</span>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="扫描" width="70" align="right" prop="scan_count">
          <template #default="{ row }">
            <el-link v-if="row.scan_count > 0" type="primary" @click.stop="$router.push(`/findings?project=${row.id}`)">
              {{ row.scan_count }}
            </el-link>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="漏洞" width="80" align="right" prop="open_finding_count">
          <template #default="{ row }">
            <el-tag v-if="row.open_finding_count > 0" type="danger" size="small">
              {{ row.open_finding_count }}
            </el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="120">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="goManage(row)">详情</el-button>
            <el-button link type="primary" size="small" @click.stop="goNewProject(row.customer_id)">源码</el-button>
            <el-button link type="warning" size="small" @click.stop="onSuspend(row)" v-if="row.status === 'active'">暂停</el-button>
            <el-button link type="success" size="small" @click.stop="onResume(row)" v-else-if="row.status === 'paused'">恢复</el-button>
            <el-button
              link type="danger"
              size="small"
              :loading="deletingId === row.id"
              @click.stop="onDelete(row)"
            >删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && filteredRows.length === 0" description="当前租户暂无项目">
        <el-button type="primary" @click="openCreate">+ 新建项目</el-button>
      </el-empty>
    </el-card>

    <!-- 新建项目对话框（最少字段：客户 + 名称 + 分支） -->
    <el-dialog v-model="createOpen" title="新建项目" width="500">
      <el-form :model="createForm" label-width="100">
        <el-form-item label="租户" required>
          <el-select v-model="createForm.customerId" placeholder="选择租户" filterable style="width: 100%">
            <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="项目名" required>
          <el-input v-model="createForm.name" placeholder="如: web-checkout" maxlength="100" />
        </el-form-item>
        <el-form-item label="主分支">
          <el-input v-model="createForm.defaultBranch" placeholder="main" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="onCreate">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Refresh, Search } from '@element-plus/icons-vue';
import * as scanApi from '@/api/scan';
import { listCustomers, type Customer } from '@/api/customers';

const router = useRouter();
const loading = ref(false);
const deletingId = ref<string | null>(null);
const rows = ref<any[]>([]);
const customers = ref<Customer[]>([]);
const q = ref('');
const customerFilter = ref<string>('');
const statusFilter = ref<string>('');

// New-project dialog
const createOpen = ref(false);
const creating = ref(false);
const createForm = reactive({
  customerId: '',
  name: '',
  defaultBranch: 'main',
});

function statusType(s: string) {
  return s === 'active' ? 'success' : s === 'configuring' ? 'warning' : 'info';
}

function sourceLabel(t: string) {
  return t === 'upload' ? 'ZIP' : t === 'github' ? 'GitHub' : t === 'gitlab' ? 'GitLab' : t;
}

function sourceTypeColor(t: string) {
  return t === 'upload' ? 'success' : 'info';
}

function customerSla(cid: string) {
  return customers.value.find((c) => c.id === cid)?.sla_tier ?? '—';
}

function formatDate(s: string) {
  if (!s) return '';
  const d = new Date(s);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const withSourceCount = computed(() => rows.value.filter((r) => r.source).length);
const withoutSourceCount = computed(() => rows.value.length - withSourceCount.value);

const filteredRows = computed(() => {
  let out = rows.value;
  if (customerFilter.value) out = out.filter((r) => r.customer_id === customerFilter.value);
  if (statusFilter.value) out = out.filter((r) => r.status === statusFilter.value);
  if (q.value) {
    const needle = q.value.toLowerCase();
    out = out.filter((r) =>
      r.name?.toLowerCase().includes(needle) ||
      r.customer_name?.toLowerCase().includes(needle),
    );
  }
  return out;
});

async function load() {
  loading.value = true;
  try {
    const projRes = await scanApi.listProjects();
    rows.value = projRes.items ?? [];
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '加载项目失败');
    rows.value = [];
  } finally {
    loading.value = false;
  }
}

async function loadCustomers() {
  try {
    const r = await listCustomers({ size: 100 });
    customers.value = r.items;
  } catch {}
}

let searchTimer: any;
function onSearchInput() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {}, 200);
}

function goManage(row: any) {
  router.push(`/sources/manage?project=${row.id}`);
}

function goNewProject(customerId?: string) {
  const q = customerId ? `?customerId=${customerId}` : '';
  router.push(`/projects/new${q}`);
}

function openCreate() {
  createForm.customerId = customerFilter.value || '';
  createForm.name = '';
  createForm.defaultBranch = 'main';
  createOpen.value = true;
}

async function onCreate() {
  if (!createForm.customerId || !createForm.name) {
    ElMessage.warning('租户和项目名必填');
    return;
  }
  creating.value = true;
  try {
    const project = await scanApi.createProject({
      customerId: createForm.customerId,
      name: createForm.name,
      defaultBranch: createForm.defaultBranch,
    });
    ElMessage.success(`项目「${project.name}」已创建`);
    createOpen.value = false;
    await load();
    router.push(`/sources/manage?project=${project.id}`);
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '创建失败');
  } finally {
    creating.value = false;
  }
}

async function onDelete(row: any) {
  try {
    await ElMessageBox.confirm(
      `删除项目「${row.name}」？\n\n该操作将：\n• 软删除项目（status=paused + deleted_at）\n• 级联删除所有源码记录\n• 退休所有关联目标，使 PoC 验证立即失效`,
      '确认删除项目', { type: 'warning', confirmButtonText: '删除' },
    );
  } catch {
    return;
  }
  deletingId.value = row.id;
  try {
    const result = await scanApi.deleteProject(row.id);
    ElMessage.success(`项目「${result.deleted.name}」已删除（源码已清理 / 目标已退休）`);
    await load();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '删除失败');
  } finally {
    deletingId.value = null;
  }
}

async function onSuspend(row: any) {
  try {
    await scanApi.patchProject(row.id, { status: 'paused' });
    ElMessage.success(`项目「${row.name}」已暂停`);
    await load();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '暂停失败');
  }
}

async function onResume(row: any) {
  try {
    await scanApi.patchProject(row.id, { status: 'active' });
    ElMessage.success(`项目「${row.name}」已恢复`);
    await load();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '恢复失败');
  }
}

onMounted(async () => {
  await loadCustomers();
  await load();
});
</script>

<style scoped>
.sources-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px 0; }
.subtitle { color: var(--color-text-secondary); margin: 0; }
.has-source { color: var(--color-success); font-weight: 500; }
.no-source { color: var(--color-warning); font-weight: 500; }
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; }
.muted { color: var(--color-text-secondary); }
.strong { font-weight: 600; }
.slug { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-placeholder); margin-left: 6px; }
</style>
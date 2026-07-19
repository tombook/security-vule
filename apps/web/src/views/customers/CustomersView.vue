<template>
  <div class="customers-page" v-loading="loading">
    <div class="stats-bar">
      <el-tag>总数 {{ total }}</el-tag>
      <el-tag type="success">活跃 {{ activeCount }}</el-tag>
      <el-tag type="warning" v-if="warningCount > 0">预警 {{ warningCount }}</el-tag>
    </div>

    <el-card>
      <div class="toolbar">
        <el-input v-model="q" placeholder="搜索客户名" clearable style="width: 240px" @input="debouncedFetch" />
        <el-select v-model="statusFilter" placeholder="状态" clearable style="width: 140px" @change="fetch">
          <el-option label="活跃" value="active" />
          <el-option label="暂停" value="suspended" />
          <el-option label="已删除" value="deleted" />
        </el-select>
        <el-button type="primary" :icon="Plus" @click="openCreate">+ 新建客户</el-button>
      </div>

      <el-table :data="items" stripe>
        <el-table-column prop="name" label="客户名" min-width="180">
          <template #default="{ row }">
            <span class="customer-name">{{ row.name }}</span>
            <code class="slug" v-if="row.slug">{{ row.slug }}</code>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : row.status === 'suspended' ? 'warning' : 'info'" size="small">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="contact_email" label="联系邮箱" min-width="200" />
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="240">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="goDetail(row.id)">详情</el-button>
            <el-button
              v-if="row.status === 'active'"
              link type="warning"
              size="small"
              :loading="suspendingId === row.id"
              @click="onSuspend(row)"
            >暂停</el-button>
            <el-button
              v-else-if="row.status === 'suspended'"
              link type="success"
              size="small"
              :loading="suspendingId === row.id"
              @click="onResume(row)"
            >恢复</el-button>
            <el-button
              v-if="row.status !== 'deleted'"
              link type="danger"
              size="small"
              :loading="deletingId === row.id"
              @click="onDelete(row)"
            >删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="page"
        v-model:page-size="size"
        :page-sizes="[10, 20, 50]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @current-change="fetch"
        @size-change="fetch"
        style="margin-top: 16px; justify-content: flex-end; display: flex;"
      />
    </el-card>

    <!-- ── New-customer dialog ──────────────────────────────────────── -->
    <!-- Phase 1 scope: the four fields the API requires (name + slug
         + 2 contact fields) plus the SLA tier. Industry is captured
         as a free-text field for now — we'll switch to an enum-backed
         select once the back-end surfaces the full list in
         GET /provider/v1/settings/industries.

         @submit on the form calls submitCreate so that pressing Enter
         in any input also submits (and so that the footer button's
         click is routed to the same handler). native-type button keeps
         the footer button out of the form's auto-submit behaviour
         so its click goes to @click. -->
    <el-dialog
      v-model="createOpen"
      title="新建客户"
      width="560"
      :close-on-click-modal="false"
      @closed="onCreateClosed"
    >
      <el-form
        ref="createFormRef"
        :model="createForm"
        :rules="createRules"
        label-width="100"
        label-position="right"
        @submit.prevent="submitCreate"
      >
        <el-form-item label="客户名称" prop="name" required>
          <el-input
            v-model="createForm.name"
            placeholder="如:Acme Corp"
            maxlength="120"
            show-word-limit
            @input="onNameChanged"
          />
        </el-form-item>
        <el-form-item label="Slug" prop="slug">
          <el-input
            v-model="createForm.slug"
            placeholder="自动从名称生成,可手动调整"
            maxlength="100"
          >
            <template #append>
              <el-button @click="regenerateSlug">重新生成</el-button>
            </template>
          </el-input>
          <span class="form-hint">URL 路径用,在本租户内唯一</span>
        </el-form-item>
        <el-form-item label="联系邮箱" prop="contactEmail">
          <el-input v-model="createForm.contactEmail" placeholder="ops@acme.com" />
        </el-form-item>
        <el-form-item label="联系电话" prop="contactPhone">
          <el-input v-model="createForm.contactPhone" placeholder="可选,如 +86 21 1234 5678" />
        </el-form-item>
        <el-form-item label="行业" prop="industry">
          <el-input v-model="createForm.industry" placeholder="如:金融、电商、SaaS(可选)" />
        </el-form-item>
        <el-form-item label="SLA 等级" prop="slaTier">
          <el-radio-group v-model="createForm.slaTier">
            <el-radio-button value="standard">标准</el-radio-button>
            <el-radio-button value="priority">优先</el-radio-button>
            <el-radio-button value="premium">高级</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-alert
          type="info"
          :closable="false"
          show-icon
          class="phase-hint"
        >
          <template #title>
            将自动为该客户创建 Starter 套餐的计费账户(100,000 token/月,余额 0)。
          </template>
        </el-alert>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">取消</el-button>
        <el-button
          type="primary"
          :loading="creating"
          :disabled="!isCreateValid"
          @click="submitCreate"
        >创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus';
import { Plus } from '@element-plus/icons-vue';
import {
  listCustomers, createCustomer, deleteCustomer, patchCustomer,
  type Customer, type CreateCustomerInput,
} from '@/api/customers';

const router = useRouter();

const loading = ref(false);
const deletingId = ref<string | null>(null);
const suspendingId = ref<string | null>(null);
const items = ref<Customer[]>([]);
const total = ref(0);
const page = ref(1);
const size = ref(20);
const q = ref('');
const statusFilter = ref<string>('');

const activeCount = computed(() => items.value.filter((c) => c.status === 'active').length);
const warningCount = computed(() => items.value.filter((c) => c.status === 'suspended').length);

// ── Create-customer dialog state ──────────────────────────────────
const createOpen = ref(false);
const creating = ref(false);
const createFormRef = ref<FormInstance | null>(null);
const createForm = reactive<CreateCustomerInput>({
  name: '',
  slug: '',
  contactEmail: '',
  contactPhone: '',
  industry: '',
  slaTier: 'standard',
});

// Validation rules. Slug has no client-side "must be unique in
// tenant" check — the server returns 409 on conflict and we surface
// the message back to the user via ElMessage.error.
const createRules: FormRules<CreateCustomerInput> = {
  name: [
    { required: true, message: '客户名称必填', trigger: 'blur' },
    { min: 2, max: 120, message: '长度 2-120 字符', trigger: 'blur' },
  ],
  slug: [
    { pattern: /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, message: '仅小写字母、数字、连字符;不能以 - 开头或结尾', trigger: 'blur' },
    { max: 100, message: '最长 100 字符', trigger: 'blur' },
  ],
  contactEmail: [
    { type: 'email', message: '邮箱格式不正确', trigger: 'blur' },
  ],
  contactPhone: [
    { max: 40, message: '最长 40 字符', trigger: 'blur' },
  ],
};

const isCreateValid = computed(() => {
  const name = createForm.name?.trim() ?? '';
  return name.length >= 2 && name.length <= 120;
});

/**
 * Auto-generate a URL-safe slug from the customer name. Mirrors the
 * server's fallback (apps/api/src/routes/customers.ts createSchema) so
 * a user who doesn't customise the slug still gets something stable.
 * If the name is empty we don't touch the slug — the user can type
 * a custom one.
 */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 100);
}

function onNameChanged(value: string | number) {
  const s = String(value);
  // Only auto-fill slug if the user hasn't typed one yet (i.e. it
  // still matches what we generated, or is empty).
  const generated = slugify(s);
  if (!createForm.slug || createForm.slug === slugify(createForm.name ?? '')) {
    createForm.slug = generated;
  }
}

function regenerateSlug() {
  createForm.slug = slugify(createForm.name ?? '');
}

function openCreate() {
  createForm.name = '';
  createForm.slug = '';
  createForm.contactEmail = '';
  createForm.contactPhone = '';
  createForm.industry = '';
  createForm.slaTier = 'standard';
  createOpen.value = true;
}

function onCreateClosed() {
  // Clear validation state so a re-open shows a clean form.
  createFormRef.value?.clearValidate();
}

async function submitCreate() {
  if (!createFormRef.value) return;
  try {
    await createFormRef.value.validate();
  } catch {
    return; // form rules already show inline errors
  }
  if (!isCreateValid.value) return;

  creating.value = true;
  try {
    // The API treats empty strings the same as null for optional
    // contact fields; we drop them client-side so the body stays
    // minimal.
    const payload: CreateCustomerInput = {
      name: createForm.name.trim(),
      slug: createForm.slug?.trim() || undefined,
      contactEmail: createForm.contactEmail?.trim() || undefined,
      contactPhone: createForm.contactPhone?.trim() || undefined,
      industry: createForm.industry?.trim() || undefined,
      slaTier: createForm.slaTier,
    };
    const created = await createCustomer(payload);
    ElMessage.success(`客户「${created.name}」创建成功,账单账户 ${created.billing.id.slice(0, 8)}`);
    createOpen.value = false;
    // Refresh the table — the new customer should appear at the top.
    page.value = 1;
    await fetch();
    // Jump to the detail view so the user can see contacts / projects.
    router.push(`/customers/${created.id}`);
  } catch (err: any) {
    const code = err?.response?.data?.error?.code;
    const msg =
      code === 'conflict' ? 'Slug 在本租户内已存在,请换一个'
      : code === 'forbidden' ? '当前角色无权创建客户(需 ProviderOwner/Admin)'
      : code === 'validation_error' ? '表单字段不合法,请检查'
      : err?.response?.data?.error?.message ?? err?.message ?? '创建失败';
    ElMessage.error(msg);
    // Inline the slug field if it's a uniqueness conflict.
    if (code === 'conflict' && createFormRef.value) {
      createFormRef.value.validateField('slug');
    }
  } finally {
    creating.value = false;
  }
}

let debounceTimer: number | undefined;
function debouncedFetch() {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = window.setTimeout(() => { page.value = 1; fetch(); }, 300);
}

async function fetch() {
  loading.value = true;
  try {
    const data = await listCustomers({ page: page.value, size: size.value, q: q.value || undefined, status: statusFilter.value || undefined });
    items.value = data.items;
    total.value = data.total;
  } catch (err) {
    items.value = [];
    total.value = 0;
  } finally {
    loading.value = false;
  }
}

function goDetail(id: string) {
  router.push(`/customers/${id}`);
}

async function onDelete(row: Customer) {
  try {
    await ElMessageBox.confirm(
      `删除客户「${row.name}」？\n\n该操作会：\n• 软删除客户（90 天后物理清理）\n• 级联暂停所有下属项目\n• 退休所有关联目标，使 PoC 验证立即失效`,
      '确认删除客户', { type: 'warning', confirmButtonText: '删除' },
    );
  } catch {
    return; // user cancelled
  }
  deletingId.value = row.id;
  try {
    const result = await deleteCustomer(row.id);
    ElMessage.success(
      `客户「${result.deleted.name}」已删除（项目已暂停 / 目标已退休）`,
    );
    // Restore default filter (show all, including deleted) so the user
    // sees the just-deleted row with its new status.
    statusFilter.value = '';
    page.value = 1;
    await fetch();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '删除失败');
  } finally {
    deletingId.value = null;
  }
}

async function onSuspend(row: Customer) {
  suspendingId.value = row.id;
  try {
    await patchCustomer(row.id, { status: 'suspended' });
    ElMessage.success(`客户「${row.name}」已暂停`);
    await fetch();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '暂停失败');
  } finally {
    suspendingId.value = null;
  }
}

async function onResume(row: Customer) {
  suspendingId.value = row.id;
  try {
    await patchCustomer(row.id, { status: 'active' });
    ElMessage.success(`客户「${row.name}」已恢复`);
    await fetch();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '恢复失败');
  } finally {
    suspendingId.value = null;
  }
}

function statusLabel(s: string) {
  return s === 'active' ? '●活跃' : s === 'suspended' ? '○暂停' : '✕已删';
}

function formatDate(s: string) {
  if (!s) return '';
  const d = new Date(s);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

onMounted(fetch);
</script>

<style scoped>
.customers-page { display: flex; flex-direction: column; gap: 16px; }
.stats-bar { display: flex; gap: 8px; }
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; }
.customer-name { font-weight: 500; margin-right: 8px; }
.slug { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-placeholder); }
.form-hint { display: block; font-size: 11px; color: var(--color-text-placeholder); margin-top: 2px; }
.phase-hint { margin-top: 8px; }
:deep(.el-dialog__body) { padding-top: 12px; }
</style>
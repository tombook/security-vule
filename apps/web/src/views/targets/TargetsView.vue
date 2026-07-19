<template>
  <div class="targets-page" v-loading="loading">
    <header class="page-header">
      <h2>目标管理</h2>
      <p class="subtitle">PoC 验证目标 · DVWA / Juice Shop / 自托管实例 · 健康探测</p>
    </header>

    <el-card>
      <div class="toolbar">
        <el-select v-model="customerId" placeholder="按客户过滤" clearable filterable style="width:240px" @change="load">
          <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
        </el-select>
        <el-button type="primary" :icon="Plus" @click="openCreate">+ 新建目标</el-button>
      </div>
      <el-table :data="items" stripe>
        <el-table-column label="名称" min-width="180">
          <template #default="{ row }">
            <strong>{{ row.name }}</strong>
            <code class="slug" v-if="row.project_id">→ {{ row.project_id.slice(0,8) }}</code>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="80">
          <template #default="{ row }">
            <el-tag size="small">{{ row.target_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="认证" width="80">
          <template #default="{ row }">
            <el-tag size="small" type="info">{{ row.auth_kind }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="URL" min-width="240">
          <template #default="{ row }">
            <code class="url">{{ row.base_url }}</code>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'warning'" size="small">
              {{ row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="健康" min-width="180">
          <template #default="{ row }">
            <span class="muted">{{ row.last_health || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="280">
          <template #default="{ row }">
            <el-button link type="success" size="small" @click="deploy(row)" :loading="deployingId === row.id">部署沙盒</el-button>
            <el-button link type="warning" size="small" @click="cleanup(row)" :loading="cleaningId === row.id">清理沙盒</el-button>
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="onDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="open" :title="editId ? '编辑目标' : '新建目标'" width="600">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="100">
        <el-form-item label="客户" prop="customerId">
          <el-select v-model="form.customerId" filterable placeholder="选择客户" :disabled="!!editId" style="width:100%">
            <el-option v-for="c in customers" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="项目 (可选)" prop="projectId">
          <el-select v-model="form.projectId" filterable clearable placeholder="不指定(可用于任何项目)" style="width:100%">
            <el-option v-for="p in projects" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="如:DVWA localhost" />
        </el-form-item>
        <el-form-item label="URL" prop="baseUrl">
          <el-input v-model="form.baseUrl" placeholder="https://..." />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-radio-group v-model="form.authKind">
            <el-radio-button value="none">无</el-radio-button>
            <el-radio-button value="basic">Basic</el-radio-button>
            <el-radio-button value="form">Form</el-radio-button>
            <el-radio-button value="bearer">Bearer</el-radio-button>
            <el-radio-button value="header">Header</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.authKind === 'basic' || form.authKind === 'form'" label="账号">
          <el-input v-model="form.authUsername" placeholder="用户名" />
        </el-form-item>
        <el-form-item v-if="form.authKind === 'basic' || form.authKind === 'form'" label="密码">
          <el-input v-model="form.authPassword" type="password" show-password placeholder="密码(仅写入,不返回)" />
        </el-form-item>
        <el-form-item v-if="form.authKind === 'bearer'" label="Token">
          <el-input v-model="form.authToken" type="password" show-password placeholder="Bearer token" />
        </el-form-item>
        <el-form-item label="类型">
          <el-radio-group v-model="form.targetType">
            <el-radio-button value="http">HTTP</el-radio-button>
            <el-radio-button value="https">HTTPS</el-radio-button>
            <el-radio-button value="docker">Docker</el-radio-button>
            <el-radio-button value="mock">Mock</el-radio-button>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="open = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="onSubmit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus';
import { Plus } from '@element-plus/icons-vue';
import * as api from '@/api/targets';
import { apiClient } from '@/api/client';
import { listCustomers } from '@/api/customers';
import { listProjects } from '@/api/scan';

const loading = ref(false);
const saving = ref(false);
const probingId = ref<string | null>(null);
const deployingId = ref<string | null>(null);
const cleaningId = ref<string | null>(null);
const items = ref<api.Target[]>([]);
const customers = ref<any[]>([]);
const projects = ref<any[]>([]);
const customerId = ref('');

const open = ref(false);
const editId = ref<string | null>(null);
const formRef = ref<FormInstance>();
const form = reactive<api.CreateTargetInput>({
  customerId: '', name: '', baseUrl: 'http://localhost:8081/login.php',
  targetType: 'http', authKind: 'none',
});
const rules: FormRules = {
  customerId: [{ required: true, message: '请选择客户' }],
  name: [{ required: true, min: 1, max: 120, message: '1-120 字符' }],
  baseUrl: [{ required: true, type: 'url', message: '请输入有效 URL' }],
};

async function load() {
  loading.value = true;
  try {
    const r = await api.listTargets(customerId.value ? { customerId: customerId.value } : {});
    items.value = r.items;
  } catch (err: any) {
    ElMessage.error(err.message ?? '加载目标失败');
  } finally {
    loading.value = false;
  }
}

async function loadCustomers() {
  try {
    const r = await listCustomers({ size: 100 });
    customers.value = r.items;
    if (!form.customerId && r.items.length > 0) {
      form.customerId = r.items[0].id;
    }
  } catch {}
}

async function loadProjects() {
  try {
    const r = await listProjects();
    projects.value = r.items;
  } catch {}
}

function openCreate() {
  editId.value = null;
  Object.assign(form, {
    customerId: customers.value[0]?.id ?? '',
    projectId: undefined,
    name: '', baseUrl: 'http://localhost:8081/login.php',
    targetType: 'http', authKind: 'none',
    authUsername: '', authPassword: '', authToken: '',
  });
  open.value = true;
}

function openEdit(row: api.Target) {
  editId.value = row.id;
  Object.assign(form, {
    customerId: row.customer_id,
    projectId: row.project_id ?? undefined,
    name: row.name,
    baseUrl: row.base_url,
    targetType: row.target_type,
    authKind: row.auth_kind,
    authUsername: row.auth_username ?? '',
    authPassword: '',
    authToken: '',
  });
  open.value = true;
}

async function onSubmit() {
  if (!formRef.value) return;
  await formRef.value.validate(async (valid) => {
    if (!valid) return;
    saving.value = true;
    try {
      if (editId.value) {
        const { authPassword, authToken, ...rest } = form;
        const patch = { ...rest };
        if (authPassword) patch.authPassword = authPassword;
        if (authToken) patch.authToken = authToken;
        await api.patchTarget(editId.value, patch);
        ElMessage.success('已更新');
      } else {
        await api.createTarget(form);
        ElMessage.success('已创建');
      }
      open.value = false;
      await load();
    } catch (err: any) {
      ElMessage.error(err.response?.data?.error?.message ?? '保存失败');
    } finally {
      saving.value = false;
    }
  });
}

async function probe(row: api.Target) {
  probingId.value = row.id;
  try {
    const r = await api.probeTarget(row.id);
    if (r.ok) {
      ElMessage.success(`${r.detail} (${r.latencyMs}ms)`);
    } else {
      ElMessage.warning(r.detail);
    }
    await load();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '探测失败');
  } finally {
    probingId.value = null;
  }
}

async function deploy(row: api.Target) {
  deployingId.value = row.id;
  try {
    const { data } = await apiClient.post(`/provider/v1/targets/${row.id}/deploy`);
    if (data.ok) {
      ElMessage.success(`沙盒已启动 → ${data.sandboxUrl} (${data.detectedStack}, TTL ${data.ttlMinutes}min)`);
    } else {
      ElMessage.error(`部署失败: ${data.error ?? 'unknown'}`);
    }
    await load();
  } catch (err: any) {
    const detail = err.response?.data?.error ?? err.response?.data?.buildLog ?? err.message;
    ElMessage.error(`部署失败: ${typeof detail === 'string' ? detail.slice(0, 200) : 'unknown'}`);
  } finally {
    deployingId.value = null;
  }
}

async function cleanup(row: api.Target) {
  try {
    await ElMessageBox.confirm(
      '清理沙盒将停止容器、删除镜像、删除源码。此操作不可逆。',
      '确认清理沙盒', { type: 'warning' },
    );
    cleaningId.value = row.id;
    const { data } = await apiClient.post(`/provider/v1/targets/${row.id}/cleanup`);
    if (data.ok) {
      ElMessage.success(`沙盒已清理 (容器=${data.cleaned.container}, 源码删除=${data.cleaned.sourceDeleted})`);
    }
    await load();
  } catch (err: any) {
    if (err === 'cancel') return;
    ElMessage.error(err.response?.data?.error?.message ?? '清理失败');
  } finally {
    cleaningId.value = null;
  }
}

async function onDelete(row: api.Target) {
  try {
    await ElMessageBox.confirm(`删除目标「${row.name}」?(软删除,历史 PoC 仍可查)`, '确认删除', { type: 'warning' });
    await api.deleteTarget(row.id);
    ElMessage.success('已删除');
    await load();
  } catch {
    // user cancelled
  }
}

onMounted(async () => {
  await loadCustomers();
  await loadProjects();
  await load();
});
</script>

<style scoped>
.targets-page { display: flex; flex-direction: column; gap: 16px; padding: 24px; }
.page-header h2 { margin: 0 0 4px 0; }
.subtitle { color: var(--color-text-secondary); margin: 0; font-size: 13px; }
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; }
.slug { font-family: var(--font-mono); font-size: 11px; color: var(--color-text-placeholder); margin-left: 8px; }
.url { font-family: var(--font-mono); font-size: 12px; }
.muted { color: var(--color-text-secondary); }
</style>

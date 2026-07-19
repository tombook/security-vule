<template>
  <div class="settings-page" v-loading="loading">
    <header class="page-header">
      <h2>设置</h2>
      <p class="subtitle">成员管理 · 集成 · 通知偏好</p>
    </header>

    <el-tabs v-model="activeTab">
      <el-tab-pane :label="`成员 (${members.length + invites.length})`" name="members">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>本客户成员</span>
              <el-button type="primary" size="small">+ 邀请成员</el-button>
            </div>
          </template>
          <el-table :data="members" stripe>
            <el-table-column prop="email" label="邮箱" min-width="200" />
            <el-table-column prop="fullName" label="姓名" width="140" />
            <el-table-column label="角色" width="140">
              <template #default="{ row }"><el-tag size="small">{{ row.role }}</el-tag></template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="最后登录" width="200">
              <template #default="{ row }">
                {{ row.lastLoginAt ? formatTime(row.lastLoginAt) : '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
        <el-card v-if="invites.length" class="mt">
          <template #header>待接受邀请</template>
          <el-table :data="invites" stripe>
            <el-table-column prop="email" label="邮箱" min-width="200" />
            <el-table-column label="角色" width="140">
              <template #default="{ row }"><el-tag size="small">{{ row.role }}</el-tag></template>
            </el-table-column>
            <el-table-column label="过期" width="200">
              <template #default="{ row }">{{ formatTime(row.expiresAt) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="`集成 (${integrations.webhooks.length + integrations.ticketIntegrations.length})`" name="integrations">
        <el-card>
          <template #header>Webhook 集成</template>
          <el-table :data="integrations.webhooks" stripe>
            <el-table-column prop="url" label="URL" min-width="280" />
            <el-table-column label="事件类型" min-width="200">
              <template #default="{ row }">
                <el-tag v-for="e in row.event_types" :key="e" size="small" type="info" class="mr">{{ e }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="启用" width="80">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '是' : '否' }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!integrations.webhooks.length" description="未配置 webhook" :image-size="60" />
        </el-card>
        <el-card class="mt">
          <template #header>工单系统集成</template>
          <el-table :data="integrations.ticketIntegrations" stripe>
            <el-table-column label="系统" width="100">
              <template #default="{ row }"><el-tag size="small">{{ row.system }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="display_name" label="名称" min-width="160" />
            <el-table-column prop="project_key" label="项目 Key" width="140" />
            <el-table-column prop="repo_full_name" label="仓库" min-width="200" />
            <el-table-column label="启用" width="80">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '是' : '否' }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!integrations.ticketIntegrations.length" description="未配置工单集成" :image-size="60" />
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="通知偏好" name="notifications">
        <el-card>
          <h4 style="margin: 0 0 16px;">事件订阅矩阵</h4>
          <el-table :data="notifRows" border>
            <el-table-column prop="label" label="事件" width="200" />
            <el-table-column label="邮件" align="center" width="100">
              <template #default="{ row }"><el-switch :model-value="prefs[row.key]?.email ?? false" @update:model-value="(v: boolean) => { if (prefs[row.key]) prefs[row.key].email = v }" /></template>
            </el-table-column>
            <el-table-column label="站内" align="center" width="100">
              <template #default="{ row }"><el-switch :model-value="prefs[row.key]?.in_app ?? true" @update:model-value="(v: boolean) => { if (prefs[row.key]) prefs[row.key].in_app = v }" /></template>
            </el-table-column>
            <el-table-column label="Webhook" align="center" width="100">
              <template #default="{ row }"><el-switch :model-value="prefs[row.key]?.webhook ?? false" @update:model-value="(v: boolean) => { if (prefs[row.key]) prefs[row.key].webhook = v }" /></template>
            </el-table-column>
          </el-table>
          <div class="form-actions">
            <el-button type="primary" @click="onSave">保存偏好</el-button>
          </div>
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import * as api from '@/api/customer';

const activeTab = ref('members');
const loading = ref(false);
const members = ref<api.CustomerMember[]>([]);
const invites = ref<any[]>([]);
const integrations = ref<{ webhooks: any[]; ticketIntegrations: any[] }>({ webhooks: [], ticketIntegrations: [] });
const prefs = reactive<Record<string, any>>({});

const notifRows = [
  { key: 'critical_finding', label: '高危 Finding 发现' },
  { key: 'poc_confirmed', label: 'PoC 验证可利用' },
  { key: 'scan_failed', label: '扫描失败' },
  { key: 'weekly_report', label: '周报' },
];

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

async function onSave() {
  try {
    await api.saveNotificationPrefs(prefs);
    ElMessage.success('已保存');
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '保存失败');
  }
}

async function fetchAll() {
  loading.value = true;
  try {
    const [m, i, p] = await Promise.all([api.getMembers(), api.getIntegrations(), api.getNotificationPrefs()]);
    members.value = m.members;
    invites.value = m.pendingInvites;
    integrations.value = i;
    for (const k of notifRows) {
      if (!prefs[k.key]) prefs[k.key] = { email: false, in_app: true, webhook: false };
    }
    for (const [k, v] of Object.entries(p ?? {})) {
      prefs[k] = v as any;
    }
  } finally { loading.value = false; }
}

onMounted(fetchAll);
</script>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.card-header { display: flex; align-items: center; justify-content: space-between; }
.form-actions { margin-top: 16px; text-align: right; }
.mr { margin-right: 4px; }
.mt { margin-top: 16px; }
</style>

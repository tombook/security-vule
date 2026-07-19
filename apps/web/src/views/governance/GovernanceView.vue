<template>
  <div class="gov-page" v-loading="loading">
    <header class="page-header">
      <h2>治理</h2>
      <p class="subtitle">合规框架 · 审计日志 · 团队管理 · 集成中心</p>
    </header>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="合规框架" name="compliance">
        <el-row :gutter="16">
          <el-col v-for="f in compliance.frameworks" :key="f.name" :xs="24" :sm="12" :md="6">
            <el-card class="compliance-card" shadow="hover">
              <div class="compliance-name">{{ formatName(f.name) }}</div>
              <el-tag :type="f.config?.enabled ? 'success' : 'info'">{{ f.config?.enabled ? '已启用' : '未启用' }}</el-tag>
              <div class="compliance-meta">
                上次更新: {{ f.updatedAt ? formatTime(f.updatedAt) : '-' }}
              </div>
              <div v-if="f.config?.mappings" class="compliance-mappings">
                <el-tag v-for="m in f.config.mappings" :key="m" size="small" type="info">{{ m }}</el-tag>
              </div>
            </el-card>
          </el-col>
          <el-col v-if="!compliance.frameworks.length" :span="24">
            <el-empty description="尚未配置合规框架" />
          </el-col>
        </el-row>
      </el-tab-pane>

      <el-tab-pane :label="`审计日志 (${auditLogs.length})`" name="audit">
        <div class="toolbar">
          <el-input v-model="auditActor" placeholder="按邮箱筛选" clearable style="width: 240px" @input="onAuditFilter" />
          <el-input v-model="auditResource" placeholder="按资源类型筛选" clearable style="width: 200px" @input="onAuditFilter" />
        </div>
        <el-table :data="auditLogs" stripe max-height="640">
          <el-table-column label="时间" width="160">
            <template #default="{ row }">{{ formatTime(row.occurredAt) }}</template>
          </el-table-column>
          <el-table-column prop="actorEmail" label="操作人" width="200" />
          <el-table-column prop="actorIp" label="IP" width="140" />
          <el-table-column label="事件" width="100">
            <template #default="{ row }">
              <el-tag size="small" type="info">{{ row.eventType }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="resourceType" label="资源" width="120" />
          <el-table-column prop="action" label="动作" width="100" />
          <el-table-column prop="requestId" label="请求 ID" min-width="200" />
        </el-table>
      </el-tab-pane>

      <el-tab-pane :label="`团队 (${team.members.length + team.pendingInvites.length})`" name="team">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>成员</span>
              <el-button type="primary" size="small" :icon="Plus">+ 邀请成员</el-button>
            </div>
          </template>
          <el-table :data="team.members" stripe>
            <el-table-column prop="email" label="邮箱" min-width="200" />
            <el-table-column prop="fullName" label="姓名" width="140" />
            <el-table-column label="角色" width="120">
              <template #default="{ row }"><el-tag size="small">{{ row.role }}</el-tag></template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="最后登录" width="180">
              <template #default="{ row }">
                {{ row.lastLoginAt ? formatTime(row.lastLoginAt) : '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
        <el-card v-if="team.pendingInvites.length" class="mt">
          <template #header>待接受邀请 ({{ team.pendingInvites.length }})</template>
          <el-table :data="team.pendingInvites" stripe>
            <el-table-column prop="email" label="邮箱" min-width="200" />
            <el-table-column label="角色" width="120">
              <template #default="{ row }"><el-tag size="small">{{ row.role }}</el-tag></template>
            </el-table-column>
            <el-table-column label="过期时间" width="200">
              <template #default="{ row }">{{ formatTime(row.expiresAt) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="`集成中心 (${integrations.length})`" name="integrations">
        <div class="toolbar">
          <el-button type="primary" :icon="Plus">+ 添加集成</el-button>
          <span class="hint">支持 GitHub / GitLab / Jira / Slack / Webhook 等</span>
        </div>
        <el-table :data="integrations" stripe>
          <el-table-column prop="url" label="URL" min-width="280" />
          <el-table-column label="事件类型" min-width="280">
            <template #default="{ row }">
              <el-tag v-for="e in row.eventTypes" :key="e" size="small" type="info" class="mr">{{ e }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="已投递" width="100" align="right">
            <template #default="{ row }"><span class="text-success">{{ row.deliveredCount }}</span></template>
          </el-table-column>
          <el-table-column label="失败" width="80" align="right">
            <template #default="{ row }">
              <span :class="row.failedCount > 0 ? 'text-high' : 'text-muted'">{{ row.failedCount }}</span>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="80">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '是' : '否' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="最后投递" width="180">
            <template #default="{ row }">{{ row.lastDeliveredAt ? formatTime(row.lastDeliveredAt) : '-' }}</template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Plus } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';

const activeTab = ref('compliance');
const loading = ref(false);

const compliance = ref<any>({ frameworks: [], summary: {} });
const auditLogs = ref<any[]>([]);
const team = ref<any>({ members: [], pendingInvites: [] });
const integrations = ref<any[]>([]);

const auditActor = ref('');
const auditResource = ref('');

function formatName(k: string) {
  return k.replace('compliance_', '').toUpperCase();
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

let auditTimer: number | undefined;
function onAuditFilter() {
  if (auditTimer) clearTimeout(auditTimer);
  auditTimer = window.setTimeout(async () => {
    const { data } = await apiClient.get('/provider/v1/governance/audit', {
      params: { actor: auditActor.value || undefined, resource_type: auditResource.value || undefined },
    });
    auditLogs.value = data.items;
  }, 300);
}

async function fetchAll() {
  loading.value = true;
  try {
    const [c, a, t, i] = await Promise.all([
      apiClient.get('/provider/v1/governance/compliance'),
      apiClient.get('/provider/v1/governance/audit'),
      apiClient.get('/provider/v1/governance/team'),
      apiClient.get('/provider/v1/governance/integrations'),
    ]);
    compliance.value = c.data;
    auditLogs.value = a.data.items;
    team.value = t.data;
    integrations.value = i.data.items;
  } finally { loading.value = false; }
}

onMounted(fetchAll);
</script>

<style scoped>
.gov-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.compliance-card { margin-bottom: 16px; }
.compliance-name { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.compliance-meta { font-size: 11px; color: var(--color-text-placeholder); margin-top: 8px; }
.compliance-mappings { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 4px; }
.mr { margin-right: 4px; }
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; }
.card-header { display: flex; align-items: center; justify-content: space-between; }
.hint { color: var(--color-text-secondary); font-size: 12px; margin-left: 12px; }
.text-success { color: #10B981; font-weight: 600; }
.text-high { color: #EF4444; font-weight: 600; }
.text-muted { color: var(--color-text-placeholder); }
.mt { margin-top: 16px; }
</style>

<template>
  <div class="settings-page" v-loading="loading">
    <header class="page-header">
      <h2>设置</h2>
      <p class="subtitle">组织信息 · API Keys · LLM Providers · 通知偏好</p>
    </header>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="组织信息" name="organization">
        <el-card>
          <el-form :model="org" label-width="160" class="org-form">
            <el-form-item label="组织名称">
              <el-input v-model="org.name" @input="orgDirty = true" />
            </el-form-item>
            <el-form-item label="Slug">
              <el-input v-model="org.slug" disabled />
            </el-form-item>
            <el-form-item label="套餐">
              <el-tag>{{ org.plan }}</el-tag>
            </el-form-item>
            <el-form-item label="状态">
              <el-tag :type="org.status === 'active' ? 'success' : 'info'">{{ org.status }}</el-tag>
            </el-form-item>
            <el-form-item label="白标配置">
              <pre class="json-block">{{ JSON.stringify(org.whiteLabel, null, 2) }}</pre>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :icon="Check" @click="onSaveOrg" :disabled="!orgDirty">保存修改</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane :label="`API Keys (${apiKeys.length})`" name="api-keys">
        <div class="toolbar">
          <el-button type="primary" :icon="Plus" @click="showCreateKey = true">+ 创建 Key</el-button>
          <span class="hint">用于 CI/CD 插件、第三方集成</span>
        </div>
        <el-table :data="apiKeys" stripe>
          <el-table-column prop="name" label="名称" min-width="160" />
          <el-table-column label="前缀" width="200">
            <template #default="{ row }"><code>{{ row.keyPrefix }}***</code></template>
          </el-table-column>
          <el-table-column label="范围" min-width="200">
            <template #default="{ row }">
              <el-tag v-for="s in row.scopes" :key="s" size="small" class="mr">{{ s }}</el-tag>
              <span v-if="!row.scopes?.length" class="muted">无</span>
            </template>
          </el-table-column>
          <el-table-column label="最后使用" width="180">
            <template #default="{ row }">{{ row.lastUsedAt ? formatTime(row.lastUsedAt) : '从未' }}</template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag v-if="row.isActive" type="success" size="small">活跃</el-tag>
              <el-tag v-else type="info" size="small">已撤销</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button v-if="row.isActive" link type="danger" size="small" @click="onRevoke(row)">撤销</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="LLM Providers" name="llm-providers">
        <div class="toolbar">
          <el-button type="primary" :icon="Plus" @click="onAddProvider">新增 Provider</el-button>
          <el-button type="success" :icon="Check" @click="onSaveLlmProviders" :disabled="!llmProvidersDirty">保存全部</el-button>
          <el-button :icon="Refresh" @click="fetchLlmProviders">重置</el-button>
        </div>
        <el-empty v-if="llmProviders.length === 0" description="尚未配置任何 LLM Provider，点击「新增 Provider」开始" />
        <el-card v-for="(prov, idx) in llmProviders" :key="prov.id" class="provider-card" style="margin-bottom:16px;">
          <div class="provider-header">
            <div class="provider-name">
              <el-select v-model="prov.provider" size="small" style="width:130px;" @change="onProviderTypeChange(prov)">
                <el-option value="ollama" label="Ollama" />
                <el-option value="openai" label="OpenAI" />
                <el-option value="anthropic" label="Anthropic" />
                <el-option value="glm" label="智谱 GLM" />
                <el-option value="deepseek" label="DeepSeek" />
                <el-option value="custom" label="自定义" />
              </el-select>
              <el-input v-model="prov.name" size="small" style="width:200px;margin-left:8px;" placeholder="显示名称" @input="llmProvidersDirty = true" />
            </div>
            <div class="provider-actions">
              <el-switch v-model="prov.enabled" active-text="启用" @change="llmProvidersDirty = true" />
              <span class="hint" style="margin-left:16px;">优先级</span>
              <el-input-number v-model="prov.priority" :min="1" :max="99" size="small" @change="llmProvidersDirty = true" />
              <el-button size="small" type="warning" :icon="Connection" :loading="prov._testing" @click="onTestProvider(prov)" style="margin-left:8px;">测试连接</el-button>
              <el-button size="small" type="danger" :icon="Delete" @click="onDeleteProvider(idx)" style="margin-left:8px;" circle />
            </div>
          </div>
          <el-form label-width="140" size="default" style="margin-top:16px;">
            <el-form-item label="默认模型">
              <el-select v-model="prov.defaultModel" style="width:400px;" filterable allow-create @change="llmProvidersDirty = true">
                <el-option v-for="m in prov.modelOptions" :key="m" :value="m" :label="m" />
              </el-select>
            </el-form-item>
            <el-form-item label="API Key" v-if="prov.provider !== 'ollama'">
              <el-input v-model="prov.apiKey" show-password style="width:600px;" placeholder="sk-..." @input="llmProvidersDirty = true" />
            </el-form-item>
            <el-form-item label="Base URL" v-if="prov.provider === 'ollama' || prov.provider === 'custom' || prov.provider === 'glm' || prov.provider === 'deepseek' || prov.provider === 'openai'">
              <el-input v-model="prov.baseUrl" style="width:600px;" placeholder="https://api.minimaxi.com/v1" @input="llmProvidersDirty = true" />
            </el-form-item>
            <el-form-item label="备选模型">
              <el-input v-model="prov._modelOptionsString" style="width:600px;" placeholder="gpt-4o-mini, gpt-4o, o1-mini" @input="updateModelOptions(prov)" />
              <span class="hint" style="margin-left:8px;">逗号分隔</span>
            </el-form-item>
            <el-form-item label="输入价格" v-if="prov.provider !== 'ollama'">
              <el-input-number v-model="prov.inputPricePerMTok" :min="0" :step="0.1" :precision="2" size="small" /> <span class="hint">USD / 百万 token</span>
            </el-form-item>
            <el-form-item label="输出价格" v-if="prov.provider !== 'ollama'">
              <el-input-number v-model="prov.outputPricePerMTok" :min="0" :step="0.1" :precision="2" size="small" /> <span class="hint">USD / 百万 token</span>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="通知偏好" name="notifications">
        <el-card>
          <el-form label-width="200">
            <h4 style="margin: 0 0 16px;">事件订阅矩阵</h4>
            <el-table :data="notifRows" border>
              <el-table-column prop="label" label="事件" width="200" />
              <el-table-column label="邮件" align="center" width="100">
                <template #default="{ row }">
                  <el-switch
                    :model-value="prefs[row.key]?.email ?? false"
                    @update:model-value="(v: boolean) => setPref(row.key, 'email', v)"
                  />
                </template>
              </el-table-column>
              <el-table-column label="站内" align="center" width="100">
                <template #default="{ row }">
                  <el-switch
                    :model-value="prefs[row.key]?.in_app ?? true"
                    @update:model-value="(v: boolean) => setPref(row.key, 'in_app', v)"
                  />
                </template>
              </el-table-column>
              <el-table-column label="Webhook" align="center" width="100">
                <template #default="{ row }">
                  <el-switch
                    :model-value="prefs[row.key]?.webhook ?? false"
                    @update:model-value="(v: boolean) => setPref(row.key, 'webhook', v)"
                  />
                </template>
              </el-table-column>
            </el-table>
            <div class="form-actions">
              <el-button type="primary" :icon="Check" @click="onSavePrefs">保存偏好</el-button>
            </div>
          </el-form>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="showCreateKey" title="创建 API Key" width="480">
      <el-form label-width="100">
        <el-form-item label="名称" required>
          <el-input v-model="newKeyName" placeholder="如: CI/CD GitHub Action" />
        </el-form-item>
        <el-form-item label="范围">
          <el-checkbox-group v-model="newKeyScopes">
            <el-checkbox value="scan:trigger">scan:trigger</el-checkbox>
            <el-checkbox value="scan:read">scan:read</el-checkbox>
            <el-checkbox value="finding:read">finding:read</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreateKey = false">取消</el-button>
        <el-button type="primary" @click="onCreateKey" :disabled="!newKeyName.trim()">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showNewKey" title="API Key 已创建" width="540">
      <el-alert type="success" :closable="false" show-icon>
        请立即复制并妥善保存,此 key 仅显示一次。
      </el-alert>
      <pre class="key-display">{{ createdKey }}</pre>
      <template #footer>
        <el-button type="primary" @click="onCopyKey">复制</el-button>
        <el-button @click="showNewKey = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Check, Refresh, Delete, Connection } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';

const activeTab = ref('organization');
const loading = ref(false);
const orgDirty = ref(false);

const org = ref<any>({ name: '', slug: '', plan: '', status: '', whiteLabel: {} });
const apiKeys = ref<any[]>([]);
const prefs = reactive<Record<string, any>>({});
const llmProviders = ref<any[]>([]);
const llmProvidersDirty = ref(false);
const createdKey = ref('');
const showCreateKey = ref(false);
const showNewKey = ref(false);
const newKeyName = ref('');
const newKeyScopes = ref<string[]>(['scan:read', 'finding:read']);

const notifRows = [
  { key: 'critical_finding', label: '高危 Finding 发现' },
  { key: 'poc_confirmed', label: 'PoC 验证可利用' },
  { key: 'scan_failed', label: '扫描失败' },
  { key: 'quota_warning', label: '用量预警' },
  { key: 'weekly_report', label: '周报' },
];

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function setPref(key: string, channel: 'email' | 'in_app' | 'webhook', value: boolean) {
  if (!prefs[key]) prefs[key] = { email: false, in_app: true, webhook: false };
  prefs[key][channel] = value;
}

async function onCopyKey() {
  try {
    await navigator.clipboard.writeText(createdKey.value);
    ElMessage.success('已复制');
  } catch { ElMessage.error('复制失败'); }
}

async function onCreateKey() {
  try {
    const { data } = await apiClient.post('/provider/v1/settings/api-keys', {
      name: newKeyName.value.trim(),
      scopes: newKeyScopes.value,
    });
    createdKey.value = data.keyPlain;
    showCreateKey.value = false;
    showNewKey.value = true;
    newKeyName.value = '';
    newKeyScopes.value = ['scan:read', 'finding:read'];
    await fetchApiKeys();
    ElMessage.success('已创建');
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '创建失败'); }
}

async function onRevoke(row: any) {
  try {
    await ElMessageBox.confirm(`撤销 API Key "${row.name}"? 调用方将立即失效`, '撤销', { type: 'warning' });
    await apiClient.delete(`/provider/v1/settings/api-keys/${row.id}`);
    ElMessage.success('已撤销');
    await fetchApiKeys();
  } catch (e) { if (e !== 'cancel') ElMessage.error('撤销失败'); }
}

async function onSaveOrg() {
  try {
    await apiClient.put('/provider/v1/settings/organization', { name: org.value.name });
    orgDirty.value = false;
    ElMessage.success('已保存');
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '保存失败'); }
}

async function onSavePrefs() {
  try {
    await apiClient.put('/provider/v1/settings/notifications', prefs);
    ElMessage.success('已保存');
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '保存失败'); }
}

// ── LLM Provider CRUD ──────────────────────────────────────────
const PROVIDER_DEFAULTS: Record<string, { name: string; defaultModel: string; modelOptions: string[]; baseUrl: string }> = {
  ollama: { name: 'Ollama (Local)', defaultModel: 'security-vule-poc-v1', modelOptions: ['security-vule-poc-v1', 'llama3.1', 'qwen2.5'], baseUrl: 'http://localhost:11434' },
  openai: { name: 'OpenAI', defaultModel: 'gpt-4o-mini', modelOptions: ['gpt-4o-mini', 'gpt-4o', 'o1-mini'], baseUrl: '' },
  anthropic: { name: 'Anthropic', defaultModel: 'claude-sonnet-4-5', modelOptions: ['claude-sonnet-4-5', 'claude-haiku-3-5', 'claude-opus-4'], baseUrl: '' },
  glm: { name: '智谱 GLM', defaultModel: 'glm-4-flash', modelOptions: ['glm-4-flash', 'glm-4', 'glm-5.2'], baseUrl: 'https://open.bigmodel.cn/api/paas/v4' },
  deepseek: { name: 'DeepSeek', defaultModel: 'deepseek-chat', modelOptions: ['deepseek-chat', 'deepseek-reasoner'], baseUrl: 'https://api.deepseek.com' },
  custom: { name: '自定义 (OpenAI 兼容)', defaultModel: '', modelOptions: [], baseUrl: '' },
};

async function fetchLlmProviders() {
  const { data } = await apiClient.get('/provider/v1/settings/llm-providers');
  llmProviders.value = (data.items ?? []).map((p: any) => ({
    ...p,
    apiKey: p.apiKey ?? '',
    baseUrl: p.baseUrl ?? '',
    inputPricePerMTok: p.inputPricePerMTok ?? 0,
    outputPricePerMTok: p.outputPricePerMTok ?? 0,
    _modelOptionsString: (p.modelOptions ?? []).join(', '),
    _testing: false,
  }));
  llmProvidersDirty.value = false;
}

function updateModelOptions(prov: any) {
  prov.modelOptions = prov._modelOptionsString.split(',').map((s: string) => s.trim()).filter((s: string) => s);
  llmProvidersDirty.value = true;
}

function onAddProvider() {
  const id = 'prov-' + Date.now().toString(36);
  const d = PROVIDER_DEFAULTS['ollama'];
  llmProviders.value.push({
    id,
    provider: 'ollama',
    name: d.name,
    enabled: false,
    priority: llmProviders.value.length + 1,
    apiKey: '',
    baseUrl: d.baseUrl,
    defaultModel: d.defaultModel,
    modelOptions: [...d.modelOptions],
    inputPricePerMTok: 0,
    outputPricePerMTok: 0,
    _modelOptionsString: d.modelOptions.join(', '),
    _testing: false,
  });
  llmProvidersDirty.value = true;
}

function onProviderTypeChange(prov: any) {
  const d = PROVIDER_DEFAULTS[prov.provider];
  if (d) {
    prov.name = d.name;
    prov.defaultModel = d.defaultModel;
    prov.modelOptions = [...d.modelOptions];
    prov._modelOptionsString = d.modelOptions.join(', ');
    prov.baseUrl = d.baseUrl;
  }
  llmProvidersDirty.value = true;
}

async function onDeleteProvider(idx: number) {
  const prov = llmProviders.value[idx];
  try {
    await ElMessageBox.confirm(`确定删除 "${prov.name}" ?`, '删除 Provider', { type: 'warning' });
    // If already saved to DB, call DELETE
    if (!prov.id.startsWith('prov-')) {
      await apiClient.delete(`/provider/v1/settings/llm-providers/${prov.id}`);
    }
    llmProviders.value.splice(idx, 1);
    ElMessage.success('已删除');
  } catch (e) { if (e !== 'cancel') ElMessage.error('删除失败'); }
}

async function onSaveLlmProviders() {
  try {
    const payload = llmProviders.value.map((p: any) => ({
      id: p.id,
      provider: p.provider,
      name: p.name,
      enabled: p.enabled,
      priority: p.priority,
      apiKey: p.apiKey || null,
      baseUrl: p.baseUrl || null,
      defaultModel: p.defaultModel,
      modelOptions: p.modelOptions,
      inputPricePerMTok: p.inputPricePerMTok ?? 0,
      outputPricePerMTok: p.outputPricePerMTok ?? 0,
    }));
    const { data } = await apiClient.put('/provider/v1/settings/llm-providers', payload);
    llmProviders.value = (data.items ?? []).map((p: any) => ({
      ...p,
      apiKey: '',
      baseUrl: p.baseUrl ?? '',
      inputPricePerMTok: p.inputPricePerMTok ?? 0,
      outputPricePerMTok: p.outputPricePerMTok ?? 0,
      _modelOptionsString: (p.modelOptions ?? []).join(', '),
      _testing: false,
    }));
    llmProvidersDirty.value = false;
    ElMessage.success('已保存');
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '保存失败'); }
}

async function onTestProvider(prov: any) {
  prov._testing = true;
  try {
    const { data } = await apiClient.post('/provider/v1/settings/llm-providers/test', {
      id: prov.id,
      provider: prov.provider,
      apiKey: prov.apiKey || null,
      baseUrl: prov.baseUrl || null,
      defaultModel: prov.defaultModel,
    });
    if (data.ok) {
      ElMessage.success(`连接成功! 模型: ${data.model}, 延迟: ${data.latencyMs}ms`);
    } else {
      ElMessage.error(`连接失败: ${data.error}`);
    }
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '测试失败');
  } finally {
    prov._testing = false;
  }
}

async function fetchOrg() {
  const { data } = await apiClient.get('/provider/v1/settings/organization');
  org.value = data;
}

async function fetchApiKeys() {
  const { data } = await apiClient.get('/provider/v1/settings/api-keys');
  apiKeys.value = data.items;
}

async function fetchPrefs() {
  const { data } = await apiClient.get('/provider/v1/settings/notifications');
  for (const k of notifRows) {
    if (!prefs[k.key]) prefs[k.key] = { email: false, in_app: true, webhook: false };
  }
  for (const [k, v] of Object.entries(data ?? {})) {
    prefs[k] = v;
  }
}

async function fetchAll() {
  loading.value = true;
  try {
    await Promise.all([fetchOrg(), fetchApiKeys(), fetchPrefs(), fetchLlmProviders()]);
  } finally { loading.value = false; }
}

onMounted(fetchAll);
</script>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.org-form { max-width: 720px; }
.json-block { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; max-height: 200px; overflow: auto; }
.key-display { background: #1e293b; color: #10B981; padding: 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px; word-break: break-all; }
.toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; }
.hint { color: var(--color-text-secondary); font-size: 12px; }
.mr { margin-right: 4px; }
.muted { color: var(--color-text-placeholder); }
.form-actions { margin-top: 24px; text-align: right; }
.provider-card { border-left: 3px solid #409eff; }
.provider-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.provider-name { display: flex; align-items: center; }
.provider-actions { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
</style>

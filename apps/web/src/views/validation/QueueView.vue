<template>
  <div class="queue-page" v-loading="store.loading">
    <header class="page-header">
      <h2>PoC 验证队列</h2>
      <p class="subtitle">AI 生成候选 PoC · 工程师审核 · 沙箱执行验证</p>
    </header>

    <!-- ──────  统计仪表板  ────── -->
    <div class="stats-grid">
      <div class="stat-card" @click="filterBy('all')">
        <div class="stat-value">{{ stats.total }}</div>
        <div class="stat-label">总 PoC</div>
      </div>
      <div class="stat-card pending" @click="filterBy('pending')">
        <div class="stat-value">{{ stats.pending }}</div>
        <div class="stat-label">待审</div>
      </div>
      <div class="stat-card approved" @click="filterBy('approved')">
        <div class="stat-value">{{ stats.approved }}</div>
        <div class="stat-label">已批准</div>
      </div>
      <div class="stat-card success" @click="filterBy('success')">
        <div class="stat-value">{{ stats.success }}</div>
        <div class="stat-label">已证实</div>
      </div>
      <div class="stat-card failed" @click="filterBy('failed')">
        <div class="stat-value">{{ stats.failed }}</div>
        <div class="stat-label">已失败</div>
      </div>
      <div class="stat-card ai">
        <div class="stat-value">{{ stats.aiGenerated }}</div>
        <div class="stat-label">AI 生成</div>
      </div>
      <div class="stat-card prove-rate">
        <div class="stat-value">{{ stats.proveRate }}%</div>
        <div class="stat-label">可利用率</div>
      </div>
    </div>

    <!-- ──────  LLM PoC 生成工作台  ────── -->
    <el-card class="pocgen-card" shadow="never">
      <template #header>
        <div class="pocgen-header">
          <el-icon :size="20" color="#8E44AD"><MagicStick /></el-icon>
          <span class="pocgen-title">LLM PoC 生成工作台</span>
          <el-tag size="small" type="info" effect="plain">{{ activeLlmLabel }}</el-tag>
        </div>
      </template>
      <div v-loading="pocgenLoading">
        <!-- Row 1: project + mode + LLMs + batch action buttons -->
        <el-row :gutter="12" align="middle">
          <el-col :span="6">
            <el-select v-model="pocgenProjectId" placeholder="选择项目" filterable clearable @change="onPocgenProjectChange" style="width:100%">
              <el-option v-for="p in pocgenProjects" :key="p.id" :label="`${p.name} (${p.customerName ?? '—'})`" :value="p.id" />
            </el-select>
          </el-col>
          <el-col :span="4">
            <el-select v-model="pocgenMode" placeholder="挖掘模式" style="width:100%">
              <el-option label="🤖 单 LLM" value="single" />
              <el-option label="🧠 双 LLM" value="dual" />
              <el-option label="🏛️ 多 LLM 协同" value="multi" />
            </el-select>
          </el-col>
          <el-col :span="6" v-if="pocgenMode === 'multi'">
            <el-select v-model="pocgenSelectedProviderIds" multiple collapse-tags :max-collapse-tags="2"
                       placeholder="选择 ≥2 LLM" style="width:100%">
              <el-option v-for="p in activeLlmProviders" :key="p.id" :value="p.id"
                         :label="`${p.provider === 'glm' ? 'GLM' : p.provider === 'custom' ? '自定义' : p.provider} · ${p.defaultModel}`" />
            </el-select>
          </el-col>
          <el-col :span="6" v-else>
            <el-select v-model="pocgenFindingIds" placeholder="选择 open findings（可多选）" multiple filterable :max-collapse-tags="3" collapse-tags :loading="pocgenFindingLoading" style="width:100%">
              <el-option v-for="f in pocgenCandidates" :key="f.id" :label="`[${f.severity}] ${f.title} · ${(f.file_path||'').split('/').pop()}:${f.start_line}`" :value="f.id">
                <div style="display:flex;align-items:center;gap:8px;">
                  <el-tag size="small" :type="findingSeverityType(f.severity)">{{ f.severity }}</el-tag>
                  <span style="flex:1">{{ f.title }}</span>
                  <span class="muted">{{ (f.file_path||'').split('/').pop() }}:{{ f.start_line }}</span>
                </div>
              </el-option>
            </el-select>
          </el-col>
          <el-col :span="4">
            <el-button type="primary" :icon="MagicStick" :loading="pocgenBusy"
                       :disabled="pocgenDisabled" @click="onPocgenBatch" style="width:100%">
              🤖 生成 PoC
            </el-button>
          </el-col>
        </el-row>

        <!-- Row 2 (multi mode): findings multi-select + start mining button -->
        <el-row v-if="pocgenMode === 'multi'" :gutter="12" align="middle" style="margin-top:8px;">
          <el-col :span="18">
            <el-select v-model="pocgenFindingIds" placeholder="选择 open findings（可多选）" multiple filterable :max-collapse-tags="3" collapse-tags :loading="pocgenFindingLoading" style="width:100%">
              <el-option v-for="f in pocgenCandidates" :key="f.id" :label="`[${f.severity}] ${f.title} · ${(f.file_path||'').split('/').pop()}:${f.start_line}`" :value="f.id">
                <div style="display:flex;align-items:center;gap:8px;">
                  <el-tag size="small" :type="findingSeverityType(f.severity)">{{ f.severity }}</el-tag>
                  <span style="flex:1">{{ f.title }}</span>
                  <span class="muted">{{ (f.file_path||'').split('/').pop() }}:{{ f.start_line }}</span>
                </div>
              </el-option>
            </el-select>
          </el-col>
          <el-col :span="6">
            <el-button type="success" :icon="VideoPlay" :loading="executeAllBusy"
                       :disabled="!canExecuteAll" @click="onExecuteAll" style="width:100%">
              ⚡ 批量沙箱执行 ({{ approvedAndPendingCount }})
            </el-button>
          </el-col>
        </el-row>

        <!-- Status / mode indicator -->
        <div style="margin-top:10px;font-size:13px;color:var(--color-text-secondary);">
          <span>🎛️ 模式: <b>{{ modeLabel }}</b></span>
          <span v-if="activeLlmProviders.length > 0" style="margin-left:12px;">
            | 🔌 已激活 LLMs:
            <el-tag v-for="p in activeLlmProviders" :key="p.id" size="small" style="margin-left:4px;">
              {{ p.provider === 'glm' ? 'GLM' : p.provider === 'custom' ? '自定义' : p.provider }} · {{ p.defaultModel }}
            </el-tag>
          </span>
        </div>

        <p v-if="pocgenSummary" class="pocgen-summary" :class="{ 'pocgen-summary-ok': !pocgenSummary.includes('失败') }">{{ pocgenSummary }}</p>

        <!-- 黑盒验证结果 -->
        <div v-if="blackboxResults.length > 0" class="blackbox-results" style="margin-top:12px;">
          <el-divider style="margin:8px 0;" />
          <span style="font-size:13px;font-weight:600;">⚡ 黑盒沙箱验证结果 (最近 {{ blackboxResults.length }} 个):</span>
          <el-table :data="blackboxResults" size="small" stripe style="margin-top:8px;" max-height="280">
            <el-table-column prop="provider" label="LLM" width="140" />
            <el-table-column prop="model" label="Model" width="160" />
            <el-table-column label="漏洞" min-width="180">
              <template #default="{ row }">{{ row.findingTitle }}</template>
            </el-table-column>
            <el-table-column label="结果" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.proven" type="success" effect="dark">✓ 已证实</el-tag>
                <el-tag v-else-if="row.status === 'success' && !row.proven" type="warning">已跑通</el-tag>
                <el-tag v-else-if="row.status === 'failed'" type="danger">沙箱失败</el-tag>
                <el-tag v-else type="info">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="HTTP" width="80">
              <template #default="{ row }">{{ row.httpStatus ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="输出预览" min-width="200">
              <template #default="{ row }">
                <code class="code-cell">{{ (row.stdoutPreview || '').slice(0, 80) }}</code>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </el-card>

    <!-- ──────  队列表格  ────── -->
    <el-card>
      <template #header>
        <div class="toolbar">
          <el-radio-group v-model="statusFilter" @change="reload">
            <el-radio-button value="all">全部 ({{ stats.total }})</el-radio-button>
            <el-radio-button value="pending">待审 ({{ stats.pending }})</el-radio-button>
            <el-radio-button value="approved">已批准 ({{ stats.approved }})</el-radio-button>
            <el-radio-button value="running">运行中 ({{ stats.running }})</el-radio-button>
            <el-radio-button value="success">已成功 ({{ stats.success }})</el-radio-button>
            <el-radio-button value="failed">已失败 ({{ stats.failed }})</el-radio-button>
          </el-radio-group>
          <el-button @click="reload" :icon="Refresh" />
        </div>
      </template>

      <el-table :data="store.queue" stripe @row-click="onRowClick" style="cursor:pointer" :row-class-name="rowClassName">
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusColor(row.status)" size="small" effect="dark">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="已证" width="60" align="center">
          <template #default="{ row }">
            <el-icon v-if="row.exploitProven" color="#10B981" :size="20"><CircleCheckFilled /></el-icon>
            <el-icon v-else color="#9CA3AF" :size="16"><CircleClose /></el-icon>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="row.source === 'ai' ? 'primary' : 'info'" effect="plain">
              {{ row.source === 'ai' ? '🤖 AI' : '✍ 人工' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="严重度" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="severityColor(row.finding.severity)" effect="dark">{{ row.finding.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Finding" min-width="220">
          <template #default="{ row }">
            <div class="finding-cell">
              <span class="finding-title">{{ row.finding.title }}</span>
              <span class="finding-file">📄 {{ row.finding.file }}:{{ row.finding.line }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="PoC 脚本" width="100">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="openDetail(row)">
              📜 查看 ({{ row.pocScript?.length ?? 0 }})
            </el-button>
          </template>
        </el-table-column>
        <el-table-column label="执行耗时" width="90">
          <template #default="{ row }">
            <span v-if="row.durationMs != null" :class="{ 'duration-slow': row.durationMs > 5000 }">{{ formatDuration(row.durationMs) }}</span>
            <span v-else class="text-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="创建" width="150">
          <template #default="{ row }">
            <span class="time-cell">{{ formatTime(row.createdAt) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="280" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :icon="MagicStick" :loading="generateBusy[row.id]" :disabled="row.status !== 'failed'" @click.stop="onGenerate(row)">重新生成</el-button>
            <el-button v-if="row.status === 'pending'" link type="success" size="small" :icon="Check" :loading="approveBusy[row.id]" @click.stop="onApprove(row)">批准</el-button>
            <el-button v-if="row.status === 'pending'" link type="danger" size="small" :icon="Close" :loading="rejectBusy[row.id]" @click.stop="onReject(row)">拒绝</el-button>
            <el-button v-if="row.status === 'approved'" link type="warning" size="small" :icon="VideoPlay" :loading="executeBusy[row.id]" @click.stop="onExecute(row)">执行</el-button>
            <el-button link type="info" size="small" @click.stop="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!store.loading && store.queue.length === 0" description="暂无 PoC 任务" />
    </el-card>

    <!-- ──────  详情抽屉  ────── -->
    <el-drawer v-model="detailVisible" size="70%" :title="detailTitle" direction="rtl">
      <template v-if="detailData">
        <div class="detail-meta">
          <el-tag :type="statusColor(detailData.status)" effect="dark">{{ statusLabel(detailData.status) }}</el-tag>
          <el-tag :type="severityColor(detailData.finding?.severity)" effect="dark">{{ detailData.finding?.severity }}</el-tag>
          <el-tag v-if="detailData.source === 'ai'" type="primary" effect="plain">🤖 AI 生成</el-tag>
          <el-tag v-else type="info" effect="plain">✍ 人工</el-tag>
          <el-tag v-if="detailData.exploitProven" type="success" effect="dark">✓ 已证实可利用</el-tag>
        </div>

        <el-tabs v-model="detailTab">
          <!-- PoC 脚本 -->
          <el-tab-pane label="PoC 脚本" name="script">
            <div class="detail-toolbar">
              <el-button size="small" @click="copyScript" :icon="DocumentCopy">复制</el-button>
              <span class="script-info">{{ detailData.pocScript?.length ?? 0 }} 字符 · SHA256: {{ (detailData.pocScriptHash || '').slice(0, 16) }}...</span>
            </div>
            <pre class="code-block"><code>{{ detailData.pocScript }}</code></pre>
          </el-tab-pane>

          <!-- 执行日志 -->
          <el-tab-pane v-if="detailData.stdoutLog || detailData.stderrLog || detailData.exitCode != null" label="执行日志" name="logs">
            <el-descriptions :column="3" border size="small" style="margin-bottom:12px;">
              <el-descriptions-item label="Exit Code">
                <el-tag :type="detailData.exitCode === 0 ? 'success' : 'danger'" size="small">{{ detailData.exitCode }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="耗时">{{ detailData.durationMs ?? 0 }}ms</el-descriptions-item>
              <el-descriptions-item label="HTTP 状态">{{ detailData.httpStatus ?? '—' }}</el-descriptions-item>
            </el-descriptions>
            <div v-if="detailData.stderrLog" style="margin-bottom:12px;">
              <span class="log-label">stderr</span>
              <pre class="code-block error-log"><code>{{ detailData.stderrLog }}</code></pre>
            </div>
            <div v-if="detailData.stdoutLog">
              <span class="log-label">stdout</span>
              <pre class="code-block"><code>{{ detailData.stdoutLog }}</code></pre>
            </div>
          </el-tab-pane>

          <!-- 行为分析 -->
          <el-tab-pane v-if="detailData.behaviorReport" label="行为分析" name="behavior">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="执行时长">{{ detailData.behaviorReport.durationMs }}ms</el-descriptions-item>
              <el-descriptions-item label="系统调用数">{{ detailData.behaviorReport.actions?.length ?? 0 }}</el-descriptions-item>
              <el-descriptions-item label="网络调用" :span="2">
                <el-tag v-for="(nc,i) in detailData.behaviorReport.networkCalls ?? []" :key="i" size="small" type="info" style="margin:2px;">{{ nc }}</el-tag>
                <span v-if="!detailData.behaviorReport.networkCalls?.length" class="text-muted">无</span>
              </el-descriptions-item>
              <el-descriptions-item label="访问文件" :span="2">
                <code v-for="(f,i) in detailData.behaviorReport.filesAccessed ?? []" :key="i" class="file-tag">{{ f }}</code>
                <span v-if="!detailData.behaviorReport.filesAccessed?.length" class="text-muted">无</span>
              </el-descriptions-item>
              <el-descriptions-item label="系统调用列表" :span="2">
                <ul class="action-list">
                  <li v-for="(a,i) in detailData.behaviorReport.actions ?? []" :key="i">{{ a }}</li>
                </ul>
                <span v-if="!detailData.behaviorReport.actions?.length" class="text-muted">无记录</span>
              </el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>

          <!-- Finding 详情 -->
          <el-tab-pane label="Finding 详情" name="finding">
            <el-descriptions :column="1" border>
              <el-descriptions-item label="漏洞标题">{{ detailData.finding?.title }}</el-descriptions-item>
              <el-descriptions-item label="文件位置">{{ detailData.finding?.file }}:{{ detailData.finding?.line }}</el-descriptions-item>
              <el-descriptions-item label="严重度">{{ detailData.finding?.severity }}</el-descriptions-item>
              <el-descriptions-item label="PoC 来源">{{ detailData.source === 'ai' ? 'AI 生成' : '人工编写' }}</el-descriptions-item>
              <el-descriptions-item label="创建时间">{{ formatTime(detailData.createdAt) }}</el-descriptions-item>
              <el-descriptions-item v-if="detailData.approvedAt" label="批准时间">{{ formatTime(detailData.approvedAt) }}</el-descriptions-item>
              <el-descriptions-item v-if="detailData.finishedAt" label="完成时间">{{ formatTime(detailData.finishedAt) }}</el-descriptions-item>
            </el-descriptions>
          </el-tab-pane>
        </el-tabs>

        <!-- 操作按钮 -->
        <div class="detail-actions">
          <el-button v-if="detailData.status === 'pending'" type="success" @click="onApprove(detailData); detailVisible = false" :icon="Check">批准执行</el-button>
          <el-button v-if="detailData.status === 'pending'" type="danger" plain @click="onReject(detailData); detailVisible = false" :icon="Close">拒绝</el-button>
          <el-button v-if="detailData.status === 'approved'" type="warning" @click="onExecute(detailData); detailVisible = false" :icon="VideoPlay">沙箱执行</el-button>
          <el-button v-if="detailData.status === 'failed'" type="primary" @click="onGenerate(detailData); detailVisible = false" :icon="MagicStick">重新生成</el-button>
        </div>
      </template>
    </el-drawer>

    <!-- Reject dialog -->
    <el-dialog v-model="showRejectDialog" title="拒绝 PoC" width="460">
      <el-form label-width="80">
        <el-form-item label="理由" required>
          <el-input v-model="rejectReason" type="textarea" :rows="3" placeholder="例如:漏洞无法在 mock 环境复现" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showRejectDialog = false">取消</el-button>
        <el-button type="danger" :loading="!!rejectTarget" :disabled="!rejectReason.trim()" @click="confirmReject">确认拒绝</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { MagicStick, CircleCheckFilled, CircleClose, Refresh, Check, Close, VideoPlay, DocumentCopy } from '@element-plus/icons-vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { apiClient } from '@/api/client';
import { useValidationStore } from '@/stores/validation';
import { generatePoc as apiGeneratePoc } from '@/api/validation';
import { listProjects } from '@/api/scan';
import type { PocRun } from '@/api/validation';

const router = useRouter();
const store = useValidationStore();
const statusFilter = ref('all');

const generateBusy = reactive<Record<string, boolean>>({});
const approveBusy = reactive<Record<string, boolean>>({});
const rejectBusy = reactive<Record<string, boolean>>({});
const executeBusy = reactive<Record<string, boolean>>({});

const showRejectDialog = ref(false);
const rejectTarget = ref<PocRun | null>(null);
const rejectReason = ref('');

// ── Detail drawer ──
const detailVisible = ref(false);
const detailData = ref<any>(null);
const detailTab = ref('script');
const detailTitle = computed(() => detailData.value?.finding?.title ?? 'PoC 详情');

// ── Stats ──
const stats = computed(() => {
  const q = store.queue;
  const total = q.length;
  const pending = q.filter(r => r.status === 'pending').length;
  const approved = q.filter(r => r.status === 'approved').length;
  const running = q.filter(r => r.status === 'running').length;
  const success = q.filter(r => r.status === 'success').length;
  const failed = q.filter(r => r.status === 'failed').length;
  const aiGenerated = q.filter(r => r.source === 'ai').length;
  const proven = q.filter(r => r.exploitProven).length;
  const proveRate = total > 0 ? Math.round((proven / total) * 100) : 0;
  return { total, pending, approved, running, success, failed, aiGenerated, proveRate };
});

// ── Active LLM providers (fetched from settings) ──
const activeLlmProviders = ref<any[]>([]);

const activeLlmLabel = computed(() => {
  if (activeLlmProviders.value.length === 0) return '未配置 LLM';
  return activeLlmProviders.value.map(p => `${p.provider === 'glm' ? 'GLM' : p.provider === 'custom' ? '自定义' : p.provider} ${p.defaultModel}`).join(' · ');
});

async function loadActiveLlmProviders() {
  try {
    const { data } = await apiClient.get('/provider/v1/settings/llm-providers');
    activeLlmProviders.value = (data.items ?? []).filter((p: any) => p.enabled);
  } catch { /* silent */ }
}

// ── PoC generation workbench ──
interface PocgenProject { id: string; name: string; customerName?: string; customerId?: string }
interface PocgenFinding { id: string; severity: string; title: string; file_path: string; start_line: number }

const pocgenProjects = ref<PocgenProject[]>([]);
const pocgenCandidates = ref<PocgenFinding[]>([]);
const pocgenProjectId = ref('');
const pocgenFindingIds = ref<string[]>([]);
const pocgenLoading = ref(false);
const pocgenFindingLoading = ref(false);
const pocgenBusy = ref(false);
const pocgenSummary = ref('');
// Multi-LLM collaboration state
const pocgenMode = ref<'single' | 'dual' | 'multi'>('single');
const pocgenSelectedProviderIds = ref<string[]>([]);
const executeAllBusy = ref(false);
interface BlackboxRow {
  provider: string;
  model: string;
  findingTitle: string;
  status: string;          // pending | approved | running | success | failed | timeout
  proven: boolean;
  httpStatus: number | null;
  stdoutPreview: string;
  pocRunId: string;
}
const blackboxResults = ref<BlackboxRow[]>([]);

// Disabled rules for "🤖 生成 PoC" button
const pocgenDisabled = computed(() => {
  if (!pocgenProjectId.value) return true;
  if (activeLlmProviders.value.length === 0) return true;
  if (!pocgenFindingIds.value.length) return true;
  if (pocgenMode.value === 'multi' && pocgenSelectedProviderIds.value.length < 2) return true;
  return false;
});
const approvedAndPendingCount = computed(() =>
  store.queue.filter(r => r.status === 'approved' || r.status === 'pending').length
);
const canExecuteAll = computed(() => approvedAndPendingCount.value > 0);
const modeLabel = computed(() => {
  if (pocgenMode.value === 'single') return '🤖 单 LLM (使用 #1 优先级 Provider)';
  if (pocgenMode.value === 'dual') return `🧠 双 LLM (A/B 比对：${activeLlmProviders.value.slice(0, 2).map(p => p.provider === 'glm' ? 'GLM' : p.provider === 'custom' ? '自定义' : p.provider).join(' vs ')})`;
  if (pocgenMode.value === 'multi') {
    const selected = activeLlmProviders.value.filter(p => pocgenSelectedProviderIds.value.includes(p.id));
    return `🏛️ 多 LLM 协同 (${selected.length}/${activeLlmProviders.value.length}): ${selected.map(p => p.provider === 'glm' ? 'GLM' : p.provider === 'custom' ? '自定义' : p.provider).join(', ')}`;
  }
  return '';
});

function findingSeverityType(s: string): 'danger' | 'warning' | 'info' {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'info';
}

function statusLabel(s: string) {
  return ({ pending: '待审', approved: '已批准', running: '运行中', success: '已成功', failed: '已失败', timeout: '超时', canceled: '已取消' } as Record<string,string>)[s] ?? s;
}

function statusColor(s: string): '' | 'success' | 'warning' | 'info' | 'danger' | 'primary' {
  return ({ pending: 'info', approved: 'primary', running: 'warning', success: 'success', failed: 'danger', timeout: 'warning', canceled: 'info' } as const)[s] ?? 'info';
}

function severityColor(s: string): '' | 'danger' | 'warning' | 'info' | 'primary' {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'info';
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function formatDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function rowClassName({ row }: { row: any }) {
  if (row.exploitProven) return 'row-proven';
  if (row.status === 'failed') return 'row-failed';
  return '';
}

function filterBy(status: string) {
  statusFilter.value = status;
  reload();
}

function openDetail(row: PocRun) {
  detailData.value = row;
  detailTab.value = 'script';
  // If failed, default to logs tab
  if (row.status === 'failed' || row.status === 'success') {
    detailTab.value = 'logs';
  }
  detailVisible.value = true;
}

function onRowClick(row: any, column: any) {
  // Ignore clicks on the "操作" column (buttons handle their own clicks)
  if (column && column.label === '操作') return;
  openDetail(row as PocRun);
}

async function copyScript() {
  if (!detailData.value?.pocScript) return;
  try {
    await navigator.clipboard.writeText(detailData.value.pocScript);
    ElMessage.success('已复制 PoC 脚本');
  } catch { ElMessage.error('复制失败'); }
}

// ── Handlers ──
async function onGenerate(row: PocRun) {
  generateBusy[row.id] = true;
  try {
    const res = await store.generate(row.finding.id);
    ElMessage.success(res.reused ? '复用 PoC 库成功' : `已生成 PoC (${res.id.slice(0,8)})`);
    await reload();
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '生成失败'); }
  finally { generateBusy[row.id] = false; }
}

async function onApprove(row: PocRun) {
  approveBusy[row.id] = true;
  try {
    await store.approve(row.id);
    ElMessage.success('已批准，可执行');
    await reload();
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '批准失败'); }
  finally { approveBusy[row.id] = false; }
}

async function onReject(row: PocRun) {
  rejectTarget.value = row;
  rejectReason.value = '';
  showRejectDialog.value = true;
}

async function confirmReject() {
  if (!rejectTarget.value) return;
  const target = rejectTarget.value;
  rejectBusy[target.id] = true;
  try {
    await store.reject(target.id, rejectReason.value.trim());
    ElMessage.success('已拒绝');
    showRejectDialog.value = false;
    rejectTarget.value = null;
    rejectReason.value = '';
    await reload();
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '拒绝失败'); }
  finally { rejectBusy[target.id] = false; }
}

async function onExecute(row: PocRun) {
  executeBusy[row.id] = true;
  try {
    const res = await store.execute(row.id);
    if (res.exploitProven) {
      ElMessage.success('✅ PoC 验证可利用！');
    } else {
      ElMessage.warning('❌ PoC 未证实可利用');
    }
    await reload();
  } catch (err: any) { ElMessage.error(err.response?.data?.error?.message ?? '执行失败'); }
  finally { executeBusy[row.id] = false; }
}

async function reload() {
  await store.fetchQueue(statusFilter.value);
}

// ── PoC generation workbench handlers ──
async function loadPocgenProjects() {
  pocgenLoading.value = true;
  try {
    const r = await listProjects();
    const items = (r.items || []) as any[];
    pocgenProjects.value = items.map(p => ({ id: p.id, name: p.name, customerName: p.customer_name ?? p.customerName, customerId: p.customer_id ?? p.customerId }));
  } catch (err: any) { ElMessage.error(err?.response?.data?.error?.message ?? '加载项目失败'); }
  finally { pocgenLoading.value = false; }
}

async function onPocgenProjectChange(projectId: string) {
  pocgenFindingIds.value = [];
  pocgenCandidates.value = [];
  pocgenSummary.value = '';
  if (!projectId) return;
  pocgenFindingLoading.value = true;
  try {
    const r = await apiClient.get<{ items: any[] }>('/provider/v1/findings', { params: { projectId, status: 'open', size: 100 } });
    pocgenCandidates.value = (r.data.items || []).map(f => ({ id: f.id, severity: f.severity, title: f.title, file_path: f.file_path, start_line: f.start_line }));
    if (pocgenCandidates.value.length === 0) pocgenSummary.value = '该项目暂无 open 状态的 finding。';
  } catch (err: any) { ElMessage.error(err?.response?.data?.error?.message ?? '加载 findings 失败'); }
  finally { pocgenFindingLoading.value = false; }
}

async function saveProvidersForRun(selectedIds: string[]): Promise<() => Promise<void>> {
  const allProviders = (await apiClient.get('/provider/v1/settings/llm-providers')).data.items as any[];
  const updates = allProviders.map((p) => ({
    ...p,
    enabled: selectedIds.includes(p.id),
    apiKey: p.apiKey || null,
    baseUrl: p.baseUrl,
    priority: selectedIds.includes(p.id) ? selectedIds.indexOf(p.id) + 1 : 99,
  }));
  await apiClient.put('/provider/v1/settings/llm-providers', updates);
  return async () => {
    const restore = allProviders.map((p) => ({ ...p, apiKey: p.apiKey || null, baseUrl: p.baseUrl }));
    await apiClient.put('/provider/v1/settings/llm-providers', restore);
  };
}

async function onPocgenBatch() {
  const ids = pocgenFindingIds.value;
  if (!ids.length) { ElMessage.warning('请先选择 finding'); return; }
  if (activeLlmProviders.value.length === 0) { ElMessage.warning('请先在 设置 → LLM Providers 启用至少一个 LLM'); return; }

  pocgenBusy.value = true;
  pocgenSummary.value = `正在为 ${ids.length} 个 finding 调用 LLM 生成 PoC 候选...`;

  let restoreProviders = async () => {};
  let selectedIds: string[] = [];
  if (pocgenMode.value === 'multi') {
    selectedIds = pocgenSelectedProviderIds.value;
    if (selectedIds.length < 2) { ElMessage.warning('多 LLM 模式请选择 ≥2 个'); pocgenBusy.value = false; return; }
  } else if (pocgenMode.value === 'dual') {
    selectedIds = activeLlmProviders.value.slice(0, 2).map((p: any) => p.id);
  } else {
    selectedIds = [activeLlmProviders.value[0].id];
  }

  try {
    restoreProviders = await saveProvidersForRun(selectedIds);
    await loadActiveLlmProviders();
  } catch (err: any) {
    pocgenSummary.value = `配置 Provider 失败: ${err?.response?.data?.error?.message ?? err.message}`;
    pocgenBusy.value = false;
    return;
  }

  let okCount = 0, reuseCount = 0, failCount = 0;
  // For each finding, optionally rotate through each selected LLM
  const findingsToRun = ids.slice(0, pocgenMode.value === 'multi' ? 1 : 3);
  for (const fid of findingsToRun) {
    if (pocgenMode.value === 'multi') {
      // Multi-LLM: for each selected LLM, generate independently (one PoC per LLM)
      for (const pid of selectedIds) {
        try {
          await saveProvidersForRun([pid]);
          await loadActiveLlmProviders();
          const res = await apiGeneratePoc(fid);
          if (res.reused) reuseCount++; else okCount++;
        } catch (err) { failCount++; console.error(err); }
      }
    } else {
      try {
        const res = await apiGeneratePoc(fid);
        if (res.reused) reuseCount++; else okCount++;
      } catch { failCount++; }
    }
  }
  pocgenBusy.value = false;
  const parts: string[] = [];
  if (okCount) parts.push(`✅ 新生成 ${okCount}`);
  if (reuseCount) parts.push(`♻ 复用 ${reuseCount}`);
  if (failCount) parts.push(`❌ 失败 ${failCount}`);
  pocgenSummary.value = `LLM PoC 生成完成(${pocgenMode.value === 'multi' ? '🏛️ 多 LLM 协同' : pocgenMode.value === 'dual' ? '🧠 双 LLM A/B' : '🤖 单 LLM'}): ${parts.join(' / ')}。请到下方队列审批 → ⚡ 沙箱执行。`;
  ElMessage.success(parts.join(' / ') || 'done');
  await reload();
  // Try to restore original provider config
  try { await restoreProviders(); await loadActiveLlmProviders(); } catch { /* ignore */ }
  if (pocgenProjectId.value) await onPocgenProjectChange(pocgenProjectId.value);
}

// 批量沙箱执行 (黑盒 PoC 漏洞验证)
async function onExecuteAll() {
  // Approve all 'pending' poc_runs first so they can be executed
  executeAllBusy.value = true;
  blackboxResults.value = [];
  try {
    const targets = store.queue.filter(r => r.status === 'pending' || r.status === 'approved');
    if (targets.length === 0) { ElMessage.info('没有可执行的 PoC'); return; }

    // Auto-approve pending ones in batch
    const pending = targets.filter(t => t.status === 'pending');
    if (pending.length > 0) {
      ElMessage.info(`正在自动批准 ${pending.length} 个 pending PoC...`);
      for (const t of pending) {
        try { await apiClient.post(`/provider/v1/validation/poc/${t.id}/approve`, {}); } catch { /* ignore */ }
      }
    }

    pocgenSummary.value = `⚡ 正在沙箱执行 ${targets.length} 个 PoC 候选...`;
    let proven = 0, success = 0, failed = 0;
    for (const t of targets) {
      try {
        const resp = await apiClient.post<{ exploitProven: boolean; stdout: string; stderr: string; httpStatus: number | null }>(
          `/provider/v1/validation/poc/${t.id}/execute`
        );
        const data: any = resp.data;
        const providerLabel = activeLlmProviders.value.find((p: any) => p.id === (t as any).llmProviderId);
        const blackrow: BlackboxRow = {
          provider: providerLabel?.provider ?? '未知',
          model: providerLabel?.defaultModel ?? '?',
          findingTitle: t.finding?.title ?? '?',
          status: data.exploitProven ? 'success' : 'failed',
          proven: !!data.exploitProven,
          httpStatus: data.httpStatus ?? null,
          stdoutPreview: (data.stdout || data.stderr || '').slice(0, 200),
          pocRunId: t.id,
        };
        blackboxResults.value.unshift(blackrow);
        if (blackboxResults.value.length > 30) blackboxResults.value = blackboxResults.value.slice(0, 30);
        if (data.exploitProven) proven++; else if (data.status === 'success') success++; else failed++;
      } catch (err: any) {
        blackboxResults.value.unshift({
          provider: '?', model: '?',
          findingTitle: t.finding?.title ?? '?',
          status: 'failed', proven: false, httpStatus: null,
          stdoutPreview: err?.response?.data?.error?.message ?? err.message ?? '',
          pocRunId: t.id,
        });
        failed++;
      }
    }
    pocgenSummary.value = `✅ 黑盒验证完成: ${proven} 证实 / ${success} 跑通 / ${failed} 失败 (共 ${targets.length} 个 PoC)`;
    ElMessage.success(`黑盒验证完成: ${proven} 证实 / ${failed} 失败`);
    await reload();
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? err.message);
  } finally {
    executeAllBusy.value = false;
  }
}

onMounted(async () => {
  await reload();
  await loadPocgenProjects();
  await loadActiveLlmProviders();
});
</script>

<style scoped>
.queue-page { display:flex; flex-direction:column; gap:16px; }
.page-header h2 { margin:0 0 4px; font-size:20px; }
.subtitle { color:var(--color-text-secondary); font-size:13px; margin:0; }

/* Stats grid */
.stats-grid { display:grid; grid-template-columns:repeat(7,1fr); gap:12px; }
.stat-card {
  background:var(--color-bg-card); border-radius:8px; padding:16px 12px; text-align:center;
  cursor:pointer; transition:transform .15s, box-shadow .15s; border:1px solid transparent;
}
.stat-card:hover { transform:translateY(-2px); box-shadow:0 4px 12px rgba(0,0,0,.08); }
.stat-card.pending { border-top:3px solid #909399; }
.stat-card.approved { border-top:3px solid #409eff; }
.stat-card.success { border-top:3px solid #67c23a; }
.stat-card.failed { border-top:3px solid #f56c6c; }
.stat-card.ai { border-top:3px solid #8E44AD; }
.stat-card.prove-rate { border-top:3px solid #E67E22; }
.stat-value { font-size:24px; font-weight:700; }
.stat-label { font-size:12px; color:var(--color-text-secondary); margin-top:4px; }

/* PoC gen card */
.pocgen-card { background:var(--color-bg-card); }
.pocgen-header { display:flex; align-items:center; gap:8px; }
.pocgen-title { font-weight:600; font-size:14px; }
.pocgen-summary { margin:12px 0 0; font-size:13px; color:var(--color-text-secondary); }
.pocgen-summary-ok { color:#67c23a; }
.code-cell { font-size: 11px; color: var(--color-text-secondary); background: var(--color-bg-2); padding: 2px 4px; border-radius: 3px; }

/* Table */
.toolbar { display:flex; align-items:center; justify-content:space-between; }
.finding-cell { display:flex; flex-direction:column; }
.finding-title { font-weight:500; }
.finding-file { font-family:var(--font-mono); font-size:11px; color:var(--color-text-secondary); }
.time-cell { font-size:12px; color:var(--color-text-secondary); }
.duration-slow { color:#f56c6c; font-weight:500; }
.text-muted { color:var(--color-text-placeholder); }
.muted { color:var(--color-text-secondary); font-size:11px; }

:deep(.row-proven) { background-color: rgba(103,194,58,.06) !important; }
:deep(.row-failed) { background-color: rgba(245,108,108,.06) !important; }

/* Detail drawer */
.detail-meta { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }
.detail-toolbar { display:flex; align-items:center; gap:12px; margin-bottom:8px; }
.script-info { font-size:12px; color:var(--color-text-secondary); }
.code-block {
  background:#1e293b; color:#e2e8f0; padding:16px; border-radius:6px;
  font-family:var(--font-mono); font-size:12px; overflow-x:auto; max-height:520px;
  white-space:pre-wrap; word-break:break-all;
}
.code-block code { color:inherit; }
.error-log { background:#2d1b1b; color:#f87171; }
.log-label { display:block; font-size:12px; font-weight:600; margin-bottom:4px; color:var(--color-text-secondary); }
.detail-actions { margin-top:20px; display:flex; gap:8px; flex-wrap:wrap; }
.action-list { margin:0; padding-left:20px; }
.action-list li { font-size:13px; margin:2px 0; }
.file-tag { background:#F3F4F6; padding:2px 6px; border-radius:3px; font-size:11px; margin-right:4px; }
.hint { color:var(--color-text-secondary); font-size:12px; margin-left:auto; }
</style>
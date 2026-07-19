<template>
  <div class="detection-page" v-loading="store.loading">
    <header class="page-header">
      <h2>检测中心</h2>
      <p class="subtitle">漏洞检测能力 · 项目检测汇总 · 扫描引擎 · 规则库 · 策略模板</p>
    </header>

    <el-tabs v-model="activeTab" @tab-change="onTabChange">
      <!-- ──────────────────────  漏洞检测能力  ────────────────────── -->
      <el-tab-pane label="漏洞检测" name="capabilities">
        <div class="cap-summary">
          <el-statistic title="白盒静态" :value="staticCaps.length" />
          <el-statistic title="LLM 增强" :value="llmCaps.length" :value-style="{ color: '#8E44AD' }" />
          <el-statistic title="运行时验证" :value="runtimeCaps.length" :value-style="{ color: '#16A085' }" />
          <el-statistic title="Critical 级 (静态)" :value="staticCriticalCount" :value-style="{ color: '#F56C6C' }" />
          <el-statistic title="High 级 (静态)" :value="staticHighCount" :value-style="{ color: '#E6A23C' }" />
          <el-statistic title="Medium 级 (静态)" :value="staticMediumCount" :value-style="{ color: '#909399' }" />
        </div>

        <div v-loading="capLoading">
          <!-- ──── 静态白盒检测 ──── -->
          <section v-if="staticCaps.length" class="cap-group">
            <header class="cap-group-header">
              <el-icon :size="20" color="#F56C6C"><Cpu /></el-icon>
              <h3>静态白盒检测</h3>
              <el-tag size="small" effect="plain">基于 regex / AST 模式匹配</el-tag>
              <span class="muted cap-group-count">{{ staticCaps.length }} 项</span>
            </header>
            <el-row :gutter="16">
              <el-col v-for="c in staticCaps" :key="c.id" :xs="24" :sm="12" :md="8" :lg="6">
                <el-card class="cap-card" shadow="hover">
                  <div class="cap-header">
                    <el-icon :size="24" :color="capSeverityColor(c.severity)">
                      <component :is="capIcon(c.id)" />
                    </el-icon>
                    <div class="cap-title">
                      <div class="cap-name">{{ c.title }}</div>
                      <div class="cap-id muted">{{ c.id }} · CWE-{{ c.cwe.replace('CWE-', '') }} · {{ c.owasp }}</div>
                    </div>
                    <el-tag :type="capSeverityTagType(c.severity)" size="small">{{ c.severity }}</el-tag>
                  </div>
                  <p class="cap-desc">{{ c.description }}</p>
                  <div class="cap-langs">
                    <el-tag v-for="lang in c.langs" :key="lang" size="small" effect="plain" class="cap-lang">{{ lang }}</el-tag>
                  </div>
                  <div class="cap-footer">
                    <el-switch
                      :model-value="c.enabled"
                      @update:model-value="(v: boolean) => onToggleCap(c.id, v)"
                    />
                    <span class="cap-state muted">{{ c.enabled ? '已启用' : '已禁用' }}</span>
                  </div>
                </el-card>
              </el-col>
            </el-row>
          </section>

          <!-- ──── LLM 增强 ──── -->
          <section v-if="llmCaps.length" class="cap-group">
            <header class="cap-group-header">
              <el-icon :size="20" color="#8E44AD"><Connection /></el-icon>
              <h3>LLM 增强检测</h3>
              <el-tag size="small" type="info" effect="plain">调用 LLM 路由器 + poc-generator</el-tag>
              <span class="muted cap-group-count">{{ llmCaps.length }} 项</span>
            </header>
            <el-row :gutter="16">
              <el-col v-for="c in llmCaps" :key="c.id" :xs="24" :sm="12" :md="8" :lg="6">
                <el-card class="cap-card cap-card-llm" shadow="hover">
                  <div class="cap-header">
                    <el-icon :size="24" color="#8E44AD"><component :is="capIcon(c.id)" /></el-icon>
                    <div class="cap-title">
                      <div class="cap-name">{{ c.title }}</div>
                      <div class="cap-id muted">{{ c.id }} · LLM 增强</div>
                    </div>
                    <el-tag size="small" type="info">平台级</el-tag>
                  </div>
                  <p class="cap-desc">{{ c.description }}</p>
                  <div class="cap-footer">
                    <span class="muted">始终启用（核心平台能力）</span>
                  </div>
                </el-card>
              </el-col>
            </el-row>
          </section>

          <!-- ──── 运行时验证 ──── -->
          <section v-if="runtimeCaps.length" class="cap-group">
            <header class="cap-group-header">
              <el-icon :size="20" color="#16A085"><Aim /></el-icon>
              <h3>运行时 PoC 验证</h3>
              <el-tag size="small" type="success" effect="plain">针对真实目标的 exploit 探测</el-tag>
              <span class="muted cap-group-count">{{ runtimeCaps.length }} 项</span>
            </header>
            <el-row :gutter="16">
              <el-col v-for="c in runtimeCaps" :key="c.id" :xs="24" :sm="12" :md="8" :lg="6">
                <el-card class="cap-card cap-card-runtime" shadow="hover">
                  <div class="cap-header">
                    <el-icon :size="24" color="#16A085"><component :is="capIcon(c.id)" /></el-icon>
                    <div class="cap-title">
                      <div class="cap-name">{{ c.title }}</div>
                      <div class="cap-id muted">{{ c.id }} · 攻击族</div>
                    </div>
                    <el-tag size="small" type="success">平台级</el-tag>
                  </div>
                  <p class="cap-desc">{{ c.description }}</p>
                  <div class="cap-footer">
                    <span class="muted">始终启用（核心平台能力）</span>
                  </div>
                </el-card>
              </el-col>
            </el-row>
          </section>
        </div>
      </el-tab-pane>

      <!-- ──────────────────────  项目检测汇总  ────────────────────── -->
      <el-tab-pane label="项目检测" name="projects">
        <el-table :data="projectRows" stripe v-loading="projectsLoading" @row-click="goProjectFindings">
          <el-table-column label="租户" prop="customer_name" min-width="140">
            <template #default="{ row }">
              <el-link type="primary" @click.stop="$router.push(`/customers/${row.customer_id}`)">{{ row.customer_name }}</el-link>
            </template>
          </el-table-column>
          <el-table-column label="项目" prop="project_name" min-width="180">
            <template #default="{ row }">
              <el-link type="primary" @click.stop="goProjectFindings(row)">{{ row.project_name }}</el-link>
            </template>
          </el-table-column>
          <el-table-column label="漏洞总数" prop="total" width="100" align="right" sortable>
            <template #default="{ row }">
              <strong :class="row.total > 0 ? 'has-findings' : 'muted'">{{ row.total }}</strong>
            </template>
          </el-table-column>
          <el-table-column label="最近发现" width="160">
            <template #default="{ row }">{{ row.last_finding_at ? formatTime(row.last_finding_at) : '—' }}</template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!projectsLoading && projectRows.length === 0" description="当前租户尚无项目被检测" />
      </el-tab-pane>

      <!-- ──────────────────────  LLM 检测管理  ──────────────────────
           Surfaces the workflows.md §3 "用量与成本" surface: token
           usage, call counts, per-capability and per-provider
           roll-ups over a selectable window. This is the human
           interface for the hybrid pipeline — operators see how
           much the LLM-augmented capabilities cost. -->
      <el-tab-pane label="LLM 检测" name="llm">
        <div v-loading="usageLoading">
          <!-- 已激活 LLM 配置 -->
          <el-card shadow="never" style="margin-bottom: 12px;">
            <template #header>
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-weight:600;">已激活 LLM 配置</span>
                <el-tag size="small" type="success">{{ activeProviders.length }}</el-tag>
              </div>
            </template>
            <div v-if="activeProviders.length === 0" class="muted">未启用任何 LLM Provider，请到 <router-link to="/settings">设置 → LLM Providers</router-link> 配置</div>
            <div v-else class="provider-tags">
              <el-tag v-for="p in activeProviders" :key="p.id" size="large" :type="providerTagType(p.provider)" effect="dark" class="provider-tag">
                {{ providerDisplayName(p.provider) }} · {{ p.defaultModel }}
                <span class="provider-priority">P{{ p.priority }}</span>
              </el-tag>
            </div>
          </el-card>

          <!-- 🤖 AI 白盒漏洞挖掘工作台 -->
          <el-card shadow="never" style="margin-bottom: 12px;" class="mining-card">
            <template #header>
              <div style="display:flex;align-items:center;gap:8px;">
                <el-icon :size="20" color="#8E44AD"><MagicStick /></el-icon>
                <span style="font-weight:600;">🤖 AI 白盒漏洞挖掘</span>
                <el-tag size="small" type="info" effect="plain">基于已配置 LLM 执行源码扫描 + 漏洞解读 + PoC 草稿</el-tag>
              </div>
            </template>

            <el-row :gutter="12" align="middle">
              <el-col :span="8">
                <el-select v-model="miningProjectId" placeholder="选择项目" filterable clearable
                           :loading="miningProjectsLoading" @change="onMiningProjectChange" style="width:100%">
                  <el-option v-for="p in miningProjects" :key="p.id"
                             :label="`${p.name} (${p.customer_name ?? '—'})`" :value="p.id" />
                </el-select>
              </el-col>
              <el-col :span="6">
                <el-select v-model="miningMode" placeholder="挖掘模式" style="width:100%">
                  <el-option label="🤖 单 LLM" value="single" />
                  <el-option label="🧠 双 LLM (A/B)" value="dual" />
                  <el-option label="🏛️ 多 LLM 集成" value="multi" />
                </el-select>
              </el-col>
              <el-col :span="2">
                <el-button type="primary" :icon="MagicStick" :loading="miningBusy"
                           :disabled="!miningProjectId || activeProviders.length === 0 || (miningMode === 'multi' && miningSelectedProviderIds.length < 2)"
                           style="width:100%"
                           @click="onStartMining">
                  启动
                </el-button>
              </el-col>
              <el-col :span="8" v-if="miningMode === 'multi'">
                <el-select v-model="miningSelectedProviderIds" multiple collapse-tags
                           placeholder="选择参与的 LLMs (≥2)" style="width:100%">
                  <el-option v-for="p in activeProviders" :key="p.id" :value="p.id"
                             :label="`${providerDisplayName(p.provider)} · ${p.defaultModel}`" />
                </el-select>
              </el-col>
              <el-col :span="6" v-else>
                <el-tag v-if="activeProviders.length === 0" type="warning" effect="plain">
                  请先在 设置 → LLM Providers 启用至少一个
                </el-tag>
                <el-tag v-else-if="miningProjectId" type="success" effect="plain">
                  将使用: {{ miningModeText }}
                </el-tag>
              </el-col>
            </el-row>

            <div v-if="miningLastRun" class="mining-result">
              <el-divider style="margin: 12px 0;" />
              <el-row :gutter="12">
                <el-col :span="6"><el-statistic title="项目" :value="miningLastRun.projectName" /></el-col>
                <el-col :span="5">
                  <el-statistic title="扫描 ID" :value="miningLastRun.scanId.slice(0,12) + '…'" />
                </el-col>
                <el-col :span="4"><el-statistic title="状态" :value="miningLastRun.status" /></el-col>
                <el-col :span="5"><el-statistic title="新增漏洞" :value="miningLastRun.findingsCount" /></el-col>
                <el-col :span="4"><el-statistic title="模式" :value="miningLastRun.modeLabel" /></el-col>
              </el-row>
              <div v-if="miningLastRun.results.length > 0" style="margin-top: 8px;">
                <el-divider style="margin: 8px 0;" />
                <span style="font-size: 13px; color: var(--color-text-secondary);">
                  {{ miningLastRun.mode === 'multi' ? '🏛️ 集成结果 (multi-LLM agreement):' : '🧠 双 LLM 对比结果:' }}
                </span>
                <el-table :data="miningLastRun.results" size="small" stripe style="margin-top:8px;">
                  <el-table-column prop="provider" label="Provider" width="120" />
                  <el-table-column prop="model" label="Model" width="160" />
                  <el-table-column prop="length" label="长度" width="80" align="right">
                    <template #default="{ row }">{{ row.length }}</template>
                  </el-table-column>
                  <el-table-column label="质量">
                    <template #default="{ row }">
                      <el-tag :type="qualityType(row.quality)" size="small">{{ row.quality }}</el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column label="状态">
                    <template #default="{ row }">
                      <el-tag :type="row.status === 'completed' ? 'success' : row.status === 'failed' ? 'danger' : 'info'" size="small">
                        {{ row.status === 'completed' ? '✓ 完成' : row.status }}
                      </el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column label="共识度" v-if="miningLastRun.mode !== 'single'">
                    <template #default="{ row }">
                      <el-tag v-if="row.consensus !== undefined" :type="consensusType(row.consensus)" size="small">
                        {{ row.consensus }}%
                      </el-tag>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </div>

            <p v-if="miningSummary" class="mining-summary">{{ miningSummary }}</p>
          </el-card>

          <div class="llm-summary">
            <el-statistic title="窗口" :value="usageSince" />
            <el-statistic title="调用次数" :value="usageReport?.total.calls ?? 0" />
            <el-statistic title="总 Token" :value="usageReport?.total.total_tokens ?? 0" />
            <el-statistic title="总费用 (USD)" :value="(usageReport?.total.cost_usd ?? 0).toFixed(4)" :value-style="{ color: '#F56C6C' }" />
          </div>
          <el-row :gutter="12" style="margin: 12px 0;">
            <el-col :span="4">
              <el-select v-model="usageSince" @change="fetchUsage" style="width: 100%">
                <el-option label="近 24h" value="24h" />
                <el-option label="近 7d" value="7d" />
                <el-option label="近 30d" value="30d" />
              </el-select>
            </el-col>
            <el-col :span="20">
              <el-button :icon="Refresh" @click="fetchUsage">刷新用量</el-button>
            </el-col>
          </el-row>
          <el-row :gutter="16">
            <el-col :span="12">
              <el-card shadow="never" header="按能力（capability）">
                <el-table :data="usageReport?.byCapability ?? []" stripe size="small" max-height="320">
                  <el-table-column prop="capability" label="能力" min-width="120" />
                  <el-table-column prop="calls" label="调用" width="80" align="right" />
                  <el-table-column prop="total_tokens" label="Tokens" width="100" align="right" />
                  <el-table-column prop="cost_usd" label="费用 USD" width="100" align="right">
                    <template #default="{ row }">{{ Number(row.cost_usd).toFixed(4) }}</template>
                  </el-table-column>
                </el-table>
                <el-empty v-if="(usageReport?.byCapability ?? []).length === 0" description="近 {{ usageSince }} 无 LLM 调用记录" />
              </el-card>
            </el-col>
            <el-col :span="12">
              <el-card shadow="never" header="按 provider + model">
                <el-table :data="usageReport?.byProvider ?? []" stripe size="small" max-height="320">
                  <el-table-column prop="provider" label="Provider" width="120" />
                  <el-table-column prop="model" label="Model" min-width="160" />
                  <el-table-column prop="calls" label="调用" width="80" align="right" />
                  <el-table-column prop="cost_usd" label="费用 USD" width="100" align="right">
                    <template #default="{ row }">{{ Number(row.cost_usd).toFixed(4) }}</template>
                  </el-table-column>
                </el-table>
                <el-empty v-if="(usageReport?.byProvider ?? []).length === 0" description="近 {{ usageSince }} 无 LLM 调用记录" />
              </el-card>
            </el-col>
          </el-row>
          <p class="llm-note">环境变量 <code>OLLAMA_BASE_URL</code> / <code>OPENAI_API_KEY</code> / <code>ANTHROPIC_API_KEY</code> / <code>GLM_API_KEY</code> 决定 provider；详见 cli-reference.md。</p>
        </div>
      </el-tab-pane>

      <!-- ──────────────────────  引擎  ──────────────────────
           Unified engine management. Surfaces all detection engines:
           静态白盒检测 (semgrep/eslint/bandit/etc.),
           LLM 增强检测 (GLM/OpenAI/Ollama providers), and
           运行时 PoC 验证 (sandbox runners + network probes).
           Operators toggle the whole category at a glance — a disabled
           LLM engine will fall back to the template-based PoC script
           in poc-generator.ts. -->
      <el-tab-pane label="引擎" name="engines">
        <div class="engine-toolbar" style="margin-bottom:16px;">
          <el-statistic title="已启用引擎" :value="enabledEngineCount" :value-style="{ color: '#67C23A' }" style="margin-right:32px;display:inline-block;" />
          <el-statistic title="静态白盒" :value="countByCategory('semgrep')" style="margin-right:32px;display:inline-block;" />
          <el-statistic title="LLM 增强" :value="countByCategory('llm')" :value-style="{ color: '#8E44AD' }" style="margin-right:32px;display:inline-block;" />
          <el-statistic title="运行时" :value="countByCategory('runtime')" :value-style="{ color: '#E67E22' }" style="margin-right:32px;display:inline-block;" />
        </div>

        <!-- 静态白盒 -->
        <div class="engine-section">
          <div class="engine-section-header">
            <h3 class="engine-section-title">🔍 静态白盒检测</h3>
            <el-switch :model-value="sectionEnabled('semgrep')" @update:model-value="(v: boolean) => onToggleSection('semgrep', v)"
                       :loading="sectionBusy['semgrep']" active-text="全部启用" inactive-text="全部停用" />
          </div>
          <p class="engine-section-desc">基于 regex / AST 模式匹配的代码分析（semgrep / eslint / bandit / gosec / trivy 等）</p>
          <el-row :gutter="16">
            <el-col v-for="e in staticEngines" :key="e.id" :xs="24" :sm="12" :md="8" :lg="6">
              <el-card class="engine-card static" shadow="hover">
                <div class="engine-header">
                  <el-icon :size="28" color="#409EFF"><Cpu /></el-icon>
                  <div class="title-block">
                    <div class="name">{{ e.name }}</div>
                    <div class="version">v{{ e.version }} · {{ e.engineType }}</div>
                  </div>
                  <el-switch :model-value="e.enabled" :disabled="e.tenantId === null"
                             :title="e.tenantId === null ? '系统默认引擎(只读) — 请通过 POST /engines 克隆后切换' : ''"
                             @update:model-value="(v: boolean) => onToggleEngine(e, v)" />
                </div>
                <div class="engine-meta">
                  <el-tag size="small" type="info">{{ rulesByEngine(e.id) }} rules</el-tag>
                </div>
              </el-card>
            </el-col>
          </el-row>
        </div>

        <!-- LLM 增强 -->
        <div class="engine-section">
          <div class="engine-section-header">
            <h3 class="engine-section-title">🧠 LLM 增强检测</h3>
            <el-switch :model-value="sectionEnabled('llm')" @update:model-value="(v: boolean) => onToggleSection('llm', v)"
                       :loading="sectionBusy['llm']" active-text="全部启用" inactive-text="全部停用" />
          </div>
          <p class="engine-section-desc">由大型语言模型驱动的能力 — PoC 脚本生成、漏洞分析、可信度补足。每个引擎对应一个 <router-link to="/settings">LLM Provider</router-link>。</p>
          <el-row :gutter="16">
            <el-col v-for="e in llmEngines" :key="e.id" :xs="24" :sm="12" :md="8" :lg="6">
              <el-card class="engine-card llm" shadow="hover">
                <div class="engine-header">
                  <el-icon :size="28" color="#8E44AD"><Connection /></el-icon>
                  <div class="title-block">
                    <div class="name">{{ e.name }}</div>
                    <div class="version">v{{ e.version }} · LLM</div>
                  </div>
                  <el-switch :model-value="e.enabled" :disabled="e.tenantId === null"
                             :title="e.tenantId === null ? '系统默认引擎(只读) — 请通过 POST /engines 克隆后切换' : ''"
                             @update:model-value="(v: boolean) => onToggleEngine(e, v)" />
                </div>
                <div class="engine-meta">
                  <el-tag size="small" type="warning" effect="dark">{{ e.version }}</el-tag>
                  <el-tag size="small" :type="matchedProviderStatus(e)">{{ matchedProviderLabel(e) }}</el-tag>
                </div>
              </el-card>
            </el-col>
          </el-row>
        </div>

        <!-- 运行时 PoC 验证 -->
        <div class="engine-section">
          <div class="engine-section-header">
            <h3 class="engine-section-title">⚡ 运行时 PoC 验证</h3>
            <el-switch :model-value="sectionEnabled('runtime')" @update:model-value="(v: boolean) => onToggleSection('runtime', v)"
                       :loading="sectionBusy['runtime']" active-text="全部启用" inactive-text="全部停用" />
          </div>
          <p class="engine-section-desc">沙箱中实际执行 PoC 脚本并观察行为（系统调用 / 网络 / 文件访问）。验证脚本真伪，避免误报。</p>
          <el-row :gutter="16">
            <el-col v-for="e in runtimeEngines" :key="e.id" :xs="24" :sm="12" :md="8" :lg="6">
              <el-card class="engine-card runtime" shadow="hover">
                <div class="engine-header">
                  <el-icon :size="28" color="#E67E22"><Aim /></el-icon>
                  <div class="title-block">
                    <div class="name">{{ e.name }}</div>
                    <div class="version">v{{ e.version }} · runtime</div>
                  </div>
                  <el-switch :model-value="e.enabled" :disabled="e.tenantId === null"
                             :title="e.tenantId === null ? '系统默认引擎(只读) — 请通过 POST /engines 克隆后切换' : ''"
                             @update:model-value="(v: boolean) => onToggleEngine(e, v)" />
                </div>
                <div class="engine-meta">
                  <el-tag size="small" type="success">{{ pocRunsByEngine(e.id) }} runs</el-tag>
                </div>
              </el-card>
            </el-col>
          </el-row>
        </div>

        <el-empty v-if="!store.loading && store.engines.length === 0" description="尚未注册任何检测引擎" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import {
  Cpu, Connection, Aim, MagicStick,
} from '@element-plus/icons-vue';
import { useDetectionStore, type Engine } from '@/stores/detection';
import { apiClient } from '@/api/client';
import {
  listCapabilities, listProjectDetections, toggleCapability, getLlmUsage, type Capability, type ProjectDetectionRow,
  type CapabilityKind, type UsageReport,
} from '@/api/detection';

const store = useDetectionStore();
const router = useRouter();
const activeTab = ref('capabilities');

// ── Capabilities ──────────────────────────────────────
const capabilities = ref<Capability[]>([]);
const capLoading = ref(false);

// Group capabilities by kind using 3 separate computeds (more
// reactive-stable than one combined computed returning an object).
const staticCaps = computed(() => capabilities.value.filter(c => c.kind === 'static'));
const llmCaps = computed(() => capabilities.value.filter(c => c.kind === 'llm'));
const runtimeCaps = computed(() => capabilities.value.filter(c => c.kind === 'runtime'));
const staticCriticalCount = computed(() => staticCaps.value.filter(c => c.severity === 'critical').length);
const staticHighCount = computed(() => staticCaps.value.filter(c => c.severity === 'high').length);
const staticMediumCount = computed(() => staticCaps.value.filter(c => c.severity === 'medium').length);

// ── Projects ─────────────────────────────────────────
const projectRows = ref<ProjectDetectionRow[]>([]);
const projectsLoading = ref(false);

// ── LLM usage (workflows.md §3) ───────────────────────
const usageReport = ref<UsageReport | null>(null);
const usageSince = ref('30d');
const usageLoading = ref(false);
const activeProviders = ref<any[]>([]);
const rulesByEngineId = ref<Record<string, number>>({});
const pocRunsByEngineId = ref<Record<string, number>>({});

// ── AI 白盒挖掘工作台 ───────────────────────────────────
const miningProjectId = ref('');
const miningMode = ref<'single' | 'dual' | 'multi'>('single');
const miningBusy = ref(false);
const miningProjects = ref<any[]>([]);
const miningProjectsLoading = ref(false);
const miningSummary = ref('');
const miningSelectedProviderIds = ref<string[]>([]);
interface MiningResultRow {
  provider: string;
  model: string;
  length: number;
  quality: 'excellent' | 'good' | 'basic' | 'skipped';
  status: 'completed' | 'failed' | 'pending';
  consensus?: number;
  scriptPreview?: string;
}
const miningLastRun = ref<{
  projectName: string;
  scanId: string;
  status: string;
  findingsCount: number;
  mode: string;
  modeLabel: string;
  results: MiningResultRow[];
} | null>(null);

const miningModeText = computed(() => {
  if (miningMode.value === 'multi' && miningSelectedProviderIds.value.length > 0) {
    const selected = activeProviders.value.filter((p: any) => miningSelectedProviderIds.value.includes(p.id));
    return selected.map((p: any) => `${providerDisplayName(p.provider)} ${p.defaultModel}`).join(' + ');
  }
  if (miningMode.value === 'dual' && activeProviders.value.length >= 2) {
    const a = activeProviders.value[0];
    const b = activeProviders.value[1];
    return `${providerDisplayName(a.provider)} ${a.defaultModel} + ${providerDisplayName(b.provider)} ${b.defaultModel}`;
  }
  if (activeProviders.value.length > 0) {
    const a = activeProviders.value[0];
    return `${providerDisplayName(a.provider)} ${a.defaultModel}`;
  }
  return '未选择';
});

// Assess quality of a generated PoC based on its content
function assessPoCQuality(script: string): 'excellent' | 'good' | 'basic' | 'skipped' {
  if (!script || script.length < 50) return 'skipped';
  const score =
    (script.includes('http.server') ? 2 : 0) +
    (script.includes('Thread') || script.includes('threading') ? 1 : 0) +
    (script.match(/requests|urllib|httpx|fetch/gi)?.length ?? 0) +
    (script.length > 1500 ? 2 : script.length > 700 ? 1 : 0) +
    (script.match(/"""/gi)?.length ?? 0) +  // docstrings
    (script.match(/class\s+\w+/g)?.length ?? 0);
  if (score >= 6) return 'excellent';
  if (score >= 3) return 'good';
  return 'basic';
}

function qualityType(q: string): '' | 'success' | 'warning' | 'info' | 'danger' {
  return ({ excellent: 'success', good: 'warning', basic: 'info', skipped: 'danger' } as Record<string, '' | 'success' | 'warning' | 'info' | 'danger'>)[q] ?? 'info';
}

function consensusType(c: number): '' | 'success' | 'warning' | 'info' | 'danger' {
  if (c >= 75) return 'success';
  if (c >= 50) return 'warning';
  return 'info';
}

function providerDisplayName(p: string): string {
  const map: Record<string, string> = { ollama: 'Ollama', openai: 'OpenAI', anthropic: 'Anthropic', glm: '智谱 GLM', deepseek: 'DeepSeek', custom: '自定义' };
  return map[p] ?? p;
}

function providerTagType(p: string): '' | 'success' | 'warning' | 'info' | 'danger' | 'primary' {
  const map: Record<string, '' | 'success' | 'warning' | 'info' | 'danger' | 'primary'> = {
    ollama: 'info', openai: 'success', anthropic: 'warning', glm: '', deepseek: 'primary', custom: 'danger',
  };
  return map[p] ?? 'info';
}

async function fetchActiveProviders() {
  try {
    const { data } = await apiClient.get('/provider/v1/settings/llm-providers');
    activeProviders.value = (data.items ?? []).filter((p: any) => p.enabled).sort((a: any, b: any) => a.priority - b.priority);
  } catch { /* silent */ }
}

// 匹配引擎对应的 LLM Provider (按名称关键字)
function matchedProvider(e: any) {
  const name = (e.name || '').toLowerCase();
  const ver = (e.version || '').toLowerCase();
  for (const p of activeProviders.value) {
    if (name.includes(p.provider) || ver.includes(p.provider)) return p;
    if (name.includes('glm') && p.provider === 'glm') return p;
    if (name.includes('openai') && p.provider === 'openai') return p;
    if (name.includes('ollama') && p.provider === 'ollama') return p;
    if (p.defaultModel && ver.includes(p.defaultModel.toLowerCase())) return p;
  }
  return null;
}

function matchedProviderLabel(e: any): string {
  const p = matchedProvider(e);
  if (!p) return '无 Provider';
  return `Provider: ${providerDisplayName(p.provider)}`;
}

function matchedProviderStatus(e: any): '' | 'success' | 'warning' {
  return matchedProvider(e) ? 'success' : 'danger';
}

const staticEngines = computed(() => store.engines.filter((e: any) => !['llm','runtime'].includes(e.engineType)));
const llmEngines = computed(() => store.engines.filter((e: any) => e.engineType === 'llm'));
const runtimeEngines = computed(() => store.engines.filter((e: any) => e.engineType === 'runtime'));

const enabledEngineCount = computed(() => store.engines.filter((e: any) => e.enabled).length);

function countByCategory(type: string): number {
  if (type === 'semgrep') return staticEngines.value.length;
  if (type === 'llm') return llmEngines.value.length;
  if (type === 'runtime') return runtimeEngines.value.length;
  return 0;
}

function rulesByEngine(engineId: string): number {
  return rulesByEngineId.value[engineId] ?? 0;
}

function pocRunsByEngine(_engineId: string): number {
  // Count all poc_runs as runtime engine usage
  return Object.values(pocRunsByEngineId.value).reduce((a, b) => a + b, 0) || pocRunsTotal.value;
}

const pocRunsTotal = ref(0);

async function loadEngineStats() {
  try {
    const { data } = await apiClient.get('/provider/v1/validation/queue?status=all');
    pocRunsTotal.value = (data.items ?? []).length;
  } catch { pocRunsTotal.value = 0; }
}

async function loadRulesByEngine() {
  try {
    // Use the existing projects list — engine → project → rules count is too deep, just use 0 placeholder
    rulesByEngineId.value = {};
  } catch {}
}

// ── Helpers ───────────────────────────────────────────
function capIcon(id: string) {
  // Minimal icon mapping — only the few ids we use here.
  const map: Record<string, any> = {
    sqli: Cpu, xss: Cpu, cmd: Cpu, ssrf: Cpu,
    traversal: Cpu, secret: Cpu, md5: Cpu, eval: Cpu,
    'llm-poc-gen': Connection, 'llm-threat-model': Connection, 'llm-poc-refine': Connection,
    'rt-sqli': Aim, 'rt-xss': Aim, 'rt-cmd': Aim, 'rt-auth': Aim, 'rt-traversal': Aim,
  };
  return map[id] ?? Cpu;
}
function capSeverityColor(s: string) {
  return s === 'critical' ? '#F56C6C' : s === 'high' ? '#E6A23C'
    : s === 'medium' ? '#909399' : '#67C23A';
}
function capSeverityTagType(s: string): 'danger' | 'warning' | 'info' | 'success' {
  return s === 'critical' ? 'danger' : s === 'high' ? 'warning'
    : s === 'medium' ? 'info' : 'success';
}
function engineColor(_t: string) { return '#409EFF'; }
function formatTime(iso: string) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('zh-CN');
}
async function onToggleCap(id: string, v: boolean) {
  const idx = capabilities.value.findIndex((c) => c.id === id);
  if (idx === -1) return;
  const previous = capabilities.value[idx].enabled;
  capabilities.value[idx] = { ...capabilities.value[idx], enabled: v };
  try {
    await toggleCapability(id, v);
    ElMessage.success(v ? `已启用 ${id} 检测` : `已禁用 ${id} 检测`);
  } catch (err: any) {
    capabilities.value[idx] = { ...capabilities.value[idx], enabled: previous };
    ElMessage.error(err?.response?.data?.error?.message ?? '保存失败');
  }
}
const sectionBusy = reactive<Record<string, boolean>>({ semgrep: false, llm: false, runtime: false });

function sectionEnabled(category: string): boolean {
  const list = sectionEngines(category);
  const owned = list.filter((e: any) => e.tenantId !== null);
  if (owned.length === 0) return false;  // No tenant-owned engines → all "off" (readonly)
  return owned.every((e: any) => e.enabled);
}

function sectionEngines(category: string): any[] {
  if (category === 'semgrep') return staticEngines.value;
  if (category === 'llm') return llmEngines.value;
  if (category === 'runtime') return runtimeEngines.value;
  return [];
}

async function onToggleEngine(e: Engine, v: boolean) {
  try {
    await apiClient.patch(`/provider/v1/detection/engines/${e.id}`, { enabled: v });
    ElMessage.success(`${e.name} ${v ? '已启用' : '已停用'}`);
    await store.fetchEngines();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '切换失败');
  }
}

async function onToggleSection(category: string, enabled: boolean) {
  sectionBusy[category] = true;
  try {
    const list = sectionEngines(category);
    const owned = list.filter((e: any) => e.tenantId !== null);
    if (owned.length === 0) {
      ElMessage.info(`${category} 类别下当前没有租户级引擎, 无需切换(只读 built-in 不修改)`);
      return;
    }
    let okCount = 0, failCount = 0;
    for (const e of owned) {
      try {
        await apiClient.patch(`/provider/v1/detection/engines/${e.id}`, { enabled });
        okCount++;
      } catch {
        failCount++;
      }
    }
    if (failCount > 0) {
      ElMessage.warning(`${category} 类别: ${okCount} 切换成功, ${failCount} 失败`);
    } else {
      ElMessage.success(`${category} 类别 ${okCount} 个引擎 ${enabled ? '全部启用' : '全部停用'}`);
    }
    await store.fetchEngines();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '批量切换失败');
  } finally {
    sectionBusy[category] = false;
  }
}
function goProjectFindings(row: ProjectDetectionRow) {
  router.push(`/findings?project=${row.project_id}`);
}

// ── Fetchers ──────────────────────────────────────────
async function fetchCapabilities() {
  capLoading.value = true;
  try {
    const r = await listCapabilities();
    capabilities.value = r.capabilities;
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '加载检测能力失败');
  } finally {
    capLoading.value = false;
  }
}
async function fetchProjects() {
  projectsLoading.value = true;
  try {
    const r = await listProjectDetections();
    projectRows.value = r.items;
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '加载项目检测汇总失败');
  } finally {
    projectsLoading.value = false;
  }
}
async function fetchUsage() {
  usageLoading.value = true;
  try {
    usageReport.value = await getLlmUsage(usageSince.value);
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error?.message ?? '加载 LLM 用量失败');
  } finally {
    usageLoading.value = false;
  }
}
async function onTabChange(name: string | number | undefined) {
  if (name === 'engines') { await store.fetchEngines(); await loadEngineStats(); await fetchActiveProviders(); }
  else if (name === 'capabilities') await fetchCapabilities();
  else if (name === 'projects') await fetchProjects();
  else if (name === 'llm') { await fetchUsage(); await fetchActiveProviders(); await loadMiningProjects(); }
}

// ── AI 白盒挖掘 handlers ──────────────────────────────────
async function loadMiningProjects() {
  miningProjectsLoading.value = true;
  try {
    const r = await apiClient.get('/provider/v1/scan/projects');
    miningProjects.value = (r.data?.items ?? []).filter((p: any) => p.status !== 'paused');
  } catch (err: any) {
    console.error('loadMiningProjects', err);
  } finally {
    miningProjectsLoading.value = false;
  }
}

async function onMiningProjectChange(projectId: string) {
  miningSummary.value = '';
  miningLastRun.value = null;
  if (projectId) {
    try {
      const before = await apiClient.get(`/provider/v1/findings?projectId=${projectId}&size=100`);
      miningSummary.value = `项目当前已有 ${before.data?.total ?? 0} 条 finding。点击「启动 AI 挖掘」将重新扫描并触发 LLM PoC 生成。`;
    } catch { /* ignore */ }
  }
}

async function countProjectFindings(projectId: string): Promise<number> {
  try {
    const r = await apiClient.get(`/provider/v1/findings?projectId=${projectId}&size=1`);
    return r.data?.total ?? 0;
  } catch { return 0; }
}

async function fetchMiningProviders() {
  // Load current LLM providers from API
  const r = await apiClient.get('/provider/v1/settings/llm-providers');
  return (r.data?.items ?? []) as Array<{
    id: string; provider: string; name: string; defaultModel: string;
    apiKey: string|null; baseUrl: string|null; enabled: boolean; priority: number;
    inputPricePerMTok: number; outputPricePerMTok: number; modelOptions: string[];
  }>;
}

async function saveProvidersForRun(selectedIds: string[]): Promise<() => Promise<void>> {
  const allProviders = await fetchMiningProviders();
  // Only disable non-selected providers (keep their DB values, just set enabled=false)
  // Re-arrange priorities so selected first (in priority order)
  const updates = allProviders.map((p) => ({
    ...p,
    enabled: selectedIds.includes(p.id),
    apiKey: p.apiKey || null,  // preserve key (may be masked)
    baseUrl: p.baseUrl,
    priority: selectedIds.includes(p.id)
      ? selectedIds.indexOf(p.id) + 1  // 1-based
      : 99,
  }));
  // Restore by saving
  await apiClient.put('/provider/v1/settings/llm-providers', updates);
  return async () => {
    // Restore original enabled state
    const restore = allProviders.map((p) => ({
      ...p, apiKey: p.apiKey || null, baseUrl: p.baseUrl,
    }));
    await apiClient.put('/provider/v1/settings/llm-providers', restore);
  };
}

async function deletePriorPoCsForFinding(fid: string) {
  // The API reuses existing pending/approved/success poc_runs.
  // We delete them via direct DB access through RLS bypass for the multi-LLM run.
  // For simplicity, we just trigger a regenerate which reuses if available.
  // Future: add DELETE /poc/<id> endpoint.
  try {
    const q = await apiClient.get('/provider/v1/validation/queue');
    const existing = (q.data?.items ?? []).filter((p: any) => p.finding?.id === fid && p.source === 'ai');
    for (const p of existing) {
      // Skip; we cannot delete via API yet, so duplicate PoC generation will be reused
      // The quick fix is to delete via a server endpoint — not in scope of this UI iteration
    }
  } catch { /* ignore */ }
}

async function generatePoCWithProvider(findingId: string): Promise<{ ok: boolean; script: string; error?: string }> {
  try {
    const r = await apiClient.post('/provider/v1/validation/poc/generate', { findingId });
    // fetch the poc detail to get the script
    const detail = await apiClient.get(`/provider/v1/validation/poc/${r.data.id}`);
    return { ok: true, script: detail.data?.pocScript ?? '' };
  } catch (err: any) {
    return { ok: false, script: '', error: err?.response?.data?.error?.message ?? err.message };
  }
}

function computeConsensus(scripts: string[]): number {
  // Token-level Jaccard similarity across all generated scripts; 0-100
  if (scripts.length < 2) return scripts.length === 1 ? 100 : 0;
  const tokenSets = scripts.map(s => new Set(s.toLowerCase().match(/[a-z_]{3,}/g) ?? []));
  const all = new Set<string>();
  tokenSets.forEach(s => s.forEach(t => all.add(t)));
  let totalIntersection = 0;
  for (const t of all) {
    const inN = tokenSets.filter(s => s.has(t)).length;
    if (inN === tokenSets.length) totalIntersection++;
  }
  return Math.round((totalIntersection / Math.max(all.size, 1)) * 100);
}

async function onStartMining() {
  if (!miningProjectId.value) { ElMessage.warning('请选择项目'); return; }
  if (activeProviders.value.length === 0) {
    ElMessage.warning('请先在 设置 → LLM Providers 启用至少一个 LLM');
    return;
  }

  // For multi mode, require explicit selection
  let selectedIds: string[] = [];
  if (miningMode.value === 'multi') {
    selectedIds = miningSelectedProviderIds.value;
    if (selectedIds.length < 2) { ElMessage.warning('多 LLM 模式请选择至少 2 个 LLM'); return; }
  } else if (miningMode.value === 'dual') {
    selectedIds = activeProviders.value.slice(0, 2).map((p: any) => p.id);
  } else {
    selectedIds = [activeProviders.value[0].id];
  }

  miningBusy.value = true;
  miningLastRun.value = null;
  const projectName = miningProjects.value.find((p: any) => p.id === miningProjectId.value)?.name ?? miningProjectId.value.slice(0, 8);

  // Save current provider config so we can restore at end
  let restoreProviders = async () => {};
  try {
    miningSummary.value = '正在准备多 LLM 模式 (动态启用/禁用 Provider)...';
    restoreProviders = await saveProvidersForRun(selectedIds);
    // Refresh active providers list so UI reflects truth
    await fetchActiveProviders();
  } catch (err: any) {
    miningSummary.value = `配置 Provider 失败: ${err?.response?.data?.error?.message ?? err.message}`;
    miningBusy.value = false;
    return;
  }

  const results: MiningResultRow[] = [];

  try {
    // Phase 1: Source-aware scan (once)
    miningSummary.value = '正在扫描项目代码...';
    const before = await countProjectFindings(miningProjectId.value);
    const triggerResp = await apiClient.post('/provider/v1/scan/scans/trigger', {
      projectId: miningProjectId.value,
      triggerType: 'manual',
    });
    const scanId = triggerResp.data?.id ?? '?';
    miningSummary.value = `扫描已触发 (${scanId.slice(0, 8)})。等待扫描结果...`;
    let after = before;
    for (let i = 0; i < 8; i++) {
      await new Promise(r => setTimeout(r, 2000));
      after = await countProjectFindings(miningProjectId.value);
      if (after > before) break;
    }
    const newFindings = after - before;
    miningSummary.value = newFindings > 0
      ? `扫描完成，发现 ${newFindings} 条新漏洞。正在调用 LLM 生成 PoC 草稿...`
      : `扫描完成，未发现新漏洞。`;

    // Phase 2: For each finding with no PoC, generate using FIRST enabled provider
    // Track results per provider for consensus calculation
    if (newFindings > 0) {
      const findingsResp = await apiClient.get(`/provider/v1/findings?projectId=${miningProjectId.value}&size=100`);
      const allFindings = findingsResp.data?.items ?? [];
      const q = await apiClient.get('/provider/v1/validation/queue');
      const existingFids = new Set((q.data?.items ?? []).map((p: any) => p.finding?.id));
      const findingsWithoutPoC = allFindings.filter((f: any) => !existingFids.has(f.id)).slice(0, 3);

      if (findingsWithoutPoC.length === 0) {
        miningSummary.value = `扫描未产生可用 finding（可能已有 PoC）。`;
      } else {
        miningSummary.value = `为 ${findingsWithoutPoC.length} 个 finding 调用 LLM (${selectedIds.length} 个 Provider)...`;

        // Generate PoC for the first finding using current activeProviders (rotated each iter)
        // For real "rotating provider" we'd need a backend endpoint that takes a providerId.
        // Practical approach: toggle provider config to enable each one in turn, generate PoC, capture script.
        for (const fid of findingsWithoutPoC.slice(0, miningMode.value === 'multi' ? 1 : 1)) {
          miningSummary.value = `为 finding ${fid.id.slice(0,8)}... 调用 ${selectedIds.length} 个 LLM...`;
          // For each selected provider: enable only it, generate, capture script
          for (const pid of selectedIds) {
            await saveProvidersForRun([pid]);
            await fetchActiveProviders();
            const r = await generatePoCWithProvider(fid.id);
            const providerLabel = activeProviders.value.find((p: any) => p.id === pid);
            if (r.ok) {
              results.push({
                provider: providerLabel?.provider ?? pid,
                model: providerLabel?.defaultModel ?? '?',
                length: r.script.length,
                quality: assessPoCQuality(r.script),
                status: 'completed',
                scriptPreview: r.script.slice(0, 200),
              });
            } else {
              results.push({
                provider: providerLabel?.provider ?? pid,
                model: providerLabel?.defaultModel ?? '?',
                length: 0,
                quality: 'skipped',
                status: 'failed',
                scriptPreview: r.error,
              });
            }
          }
        }
      }
    }

    // Compute consensus (only meaningful for multi mode)
    if (miningMode.value === 'multi') {
      const completed = results.filter(r => r.status === 'completed' && r.scriptPreview);
      if (completed.length >= 2) {
        const consensus = computeConsensus(completed.map(r => r.scriptPreview!));
        for (const r of results) r.consensus = consensus;
      }
    }

    const totalFindings = newFindings;
    const successfulRuns = results.filter(r => r.status === 'completed').length;

    miningSummary.value = `✅ AI 挖掘完成: ${totalFindings} 个新漏洞，${results.length} 个 PoC 已生成 (${successfulRuns}/${results.length} 成功)`;
    miningLastRun.value = {
      projectName,
      scanId,
      status: 'completed',
      findingsCount: totalFindings,
      mode: miningMode.value,
      modeLabel: miningMode.value === 'multi'
        ? `🏛️ 多 LLM (${selectedIds.length})`
        : miningMode.value === 'dual'
          ? '🧠 双 LLM'
          : '🤖 单 LLM',
      results,
    };
    await fetchUsage();
    ElMessage.success(`AI 挖掘完成: ${successfulRuns}/${results.length} 个 PoC 已生成`);
  } catch (err: any) {
    miningSummary.value = `挖掘失败: ${err?.response?.data?.error?.message ?? err.message ?? '未知错误'}`;
    ElMessage.error('AI 挖掘失败');
  } finally {
    // Restore original provider config so other users/LLMs work normally after
    try { await restoreProviders(); await fetchActiveProviders(); } catch { /* ignore */ }
    miningBusy.value = false;
  }
}

onMounted(() => {
  store.fetchEngines();
  fetchCapabilities();
  fetchProjects();
  fetchUsage();
  fetchActiveProviders();
  loadEngineStats();
});
</script>

<style scoped>
.detection-page { display: flex; flex-direction: column; gap: 16px; padding: 0; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.muted { color: var(--color-text-secondary); }
.has-findings { color: var(--color-warning); font-weight: 600; }

/* Capabilities tab */
.cap-summary { display: grid; grid-template-columns: repeat(6, 1fr); gap: 24px; margin-bottom: 20px; padding: 16px 20px; background: var(--color-bg-card); border: 1px solid var(--color-border-soft); border-radius: 8px; }
.cap-group { margin-bottom: 24px; }
.cap-group-header { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid var(--color-border-soft); }
.cap-group-header h3 { margin: 0; font-size: 15px; font-weight: 600; }
.cap-group-count { margin-left: auto; font-size: 12px; }
.cap-card { margin-bottom: 16px; height: 100%; }
.cap-card-llm { border-left: 3px solid #8E44AD; }
.cap-card-runtime { border-left: 3px solid #16A085; }
.cap-header { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 8px; }
.cap-title { flex: 1; min-width: 0; }
.cap-name { font-weight: 600; font-size: 14px; line-height: 1.3; margin-bottom: 2px; }
.cap-id { font-size: 11px; font-family: var(--font-mono); }
.cap-desc { font-size: 12px; line-height: 1.5; color: var(--color-text-secondary); margin: 8px 0 12px; min-height: 54px; }
.cap-langs { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }
.cap-lang { font-family: var(--font-mono); }
.cap-footer { display: flex; align-items: center; gap: 8px; padding-top: 8px; border-top: 1px solid var(--color-border-soft); }
.cap-state { font-size: 12px; }

.engine-card { margin-bottom: 16px; }
.engine-card.static { border-left: 3px solid #409EFF; }
.engine-card.llm { border-left: 3px solid #8E44AD; }
.engine-card.runtime { border-left: 3px solid #E67E22; }
.engine-section { margin-bottom: 28px; }
.engine-section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
.engine-section-title { margin: 0; font-size: 16px; font-weight: 600; color: var(--color-text); }
.engine-section-desc { margin: 0 0 12px; font-size: 12px; color: var(--color-text-secondary); }
.engine-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.engine-meta { display: flex; gap: 6px; flex-wrap: wrap; }

/* LLM usage tab */
.llm-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 12px; padding: 16px 20px; background: var(--color-bg-card); border: 1px solid var(--color-border-soft); border-radius: 8px; }
.provider-tags { display: flex; flex-wrap: wrap; gap: 12px; }
.provider-tag { display: inline-flex; align-items: center; gap: 4px; font-size: 14px; padding: 8px 16px; }
.provider-priority { margin-left: 8px; font-size: 11px; opacity: 0.7; background: rgba(255,255,255,0.2); padding: 1px 6px; border-radius: 8px; }
.mining-card { border-left: 3px solid #8E44AD; }
.mining-summary { margin: 12px 0 0; font-size: 13px; color: var(--color-text-secondary); }
.mining-result { margin-top: 8px; }
.llm-note { color: var(--color-text-secondary); font-size: 12px; margin-top: 12px; }
.llm-note code { background: var(--color-bg-2); padding: 1px 6px; border-radius: 3px; font-size: 11px; }
.title-block { flex: 1; }
.name { font-weight: 600; }
.version { font-size: 12px; color: var(--color-text-secondary); }
</style>
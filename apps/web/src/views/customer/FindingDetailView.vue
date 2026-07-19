<template>
  <div class="finding-detail" v-loading="loading">
    <el-button link @click="goBack">
      <el-icon><ArrowLeft /></el-icon> 返回漏洞列表
    </el-button>

    <header class="page-header" v-if="finding">
      <h2>{{ finding.title }}</h2>
      <div class="meta">
        <el-tag :type="severityColor(finding.severity)" size="large">{{ finding.severity }}</el-tag>
        <el-tag size="large">{{ finding.status }}</el-tag>
        <el-tag v-if="finding.hasPocProof" type="success" size="large">✓ PoC 已证</el-tag>
      </div>
    </header>

    <el-row :gutter="20" v-if="finding">
      <el-col :span="14">
        <el-card>
          <template #header>漏洞描述</template>
          <p class="description">{{ finding.description || '无描述' }}</p>
        </el-card>

        <el-card class="mt" v-if="finding.codeSnippet">
          <template #header>代码片段 ({{ finding.filePath }}:{{ finding.startLine }}-{{ finding.endLine }})</template>
          <pre class="code-block"><code>{{ finding.codeSnippet }}</code></pre>
        </el-card>

        <el-card class="mt">
          <template #header>状态流转</template>
          <el-timeline v-if="finding.stateHistory?.length">
            <el-timeline-item v-for="(s, i) in finding.stateHistory" :key="i" :timestamp="formatTime(s.occurred_at)" :type="i === finding.stateHistory.length - 1 ? 'primary' : ''">
              <span class="state-change">
                <code>{{ s.from_status || '新建' }}</code> → <code>{{ s.to_status }}</code>
                <span class="muted">via {{ s.change_source }}</span>
                <span v-if="s.reason" class="reason"> — {{ s.reason }}</span>
              </span>
            </el-timeline-item>
          </el-timeline>
          <el-empty v-else description="无状态变更历史" :image-size="60" />
        </el-card>
      </el-col>

      <el-col :span="10">
        <el-card>
          <template #header>属性</template>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="项目">{{ finding.projectName }}</el-descriptions-item>
            <el-descriptions-item label="规则">
              {{ finding.ruleTitle || '-' }}
            </el-descriptions-item>
            <el-descriptions-item v-if="finding.ruleDescription" label="规则说明">
              <small>{{ finding.ruleDescription }}</small>
            </el-descriptions-item>
            <el-descriptions-item label="置信度">{{ finding.confidence }}</el-descriptions-item>
            <el-descriptions-item label="引擎">
              <el-tag v-for="e in finding.engines" :key="e" size="small" class="mr">{{ e }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="CWE">
              <code v-for="c in finding.cweIds" :key="c" class="cwe-tag">{{ c }}</code>
            </el-descriptions-item>
            <el-descriptions-item label="OWASP">
              <code v-for="o in finding.owaspIds" :key="o" class="cwe-tag">{{ o }}</code>
            </el-descriptions-item>
            <el-descriptions-item label="首次发现">{{ formatTime(finding.firstSeenAt) }}</el-descriptions-item>
            <el-descriptions-item v-if="finding.confirmedAt" label="已确认时间">
              {{ formatTime(finding.confirmedAt) }}
            </el-descriptions-item>
            <el-descriptions-item v-if="finding.fixedAt" label="已修复时间">
              {{ formatTime(finding.fixedAt) }}
            </el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card v-if="finding.pocRuns?.length" class="mt">
          <template #header>PoC 验证记录</template>
          <el-alert
            v-for="p in finding.pocRuns" :key="p.id"
            :type="p.exploit_proven ? 'success' : 'info'"
            :title="`PoC ${p.id.slice(0,8)} · ${p.status} · ${p.exploit_proven ? '已证可利用' : '未证'}`"
            :closable="false" show-icon class="mb"
          />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ArrowLeft } from '@element-plus/icons-vue';
import * as api from '@/api/customer';

const route = useRoute();
const router = useRouter();
const finding = ref<api.CustomerFindingDetail | null>(null);
const loading = ref(false);

function severityColor(s: string): '' | 'danger' | 'warning' | 'info' {
  if (s === 'critical') return 'danger';
  if (s === 'high') return 'warning';
  return 'info';
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false });
}

function goBack() {
  router.push('/portal/findings');
}

async function fetch() {
  loading.value = true;
  try {
    finding.value = await api.getFinding(route.params.id as string);
  } finally { loading.value = false; }
}

onMounted(fetch);
</script>

<style scoped>
.finding-detail { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 4px 0; font-size: 20px; }
.page-header .meta { display: flex; align-items: center; gap: 8px; }
.description { color: var(--color-text-secondary); line-height: 1.6; margin: 0; }
.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 12px;
  overflow-x: auto;
  margin: 0;
}
.code-block code { color: inherit; }
.state-change { font-size: 13px; }
.muted { color: var(--color-text-placeholder); }
.reason { color: var(--color-text-secondary); font-style: italic; }
.cwe-tag { background: #EEF2FF; color: #4F46E5; padding: 1px 5px; border-radius: 3px; font-size: 10px; margin-right: 4px; }
.mr { margin-right: 4px; }
.mb { margin-bottom: 8px; }
.mt { margin-top: 16px; }
</style>

<template>
  <div class="finding-detail" v-loading="loading">
    <header class="page-header">
      <div>
        <el-link @click="$router.push('/findings')">← 返回 Findings</el-link>
        <h2>{{ finding?.title }}</h2>
        <div class="meta">
          <el-tag v-if="finding" :type="severityType(finding.severity)" size="large">{{ finding.severity }}</el-tag>
          <el-tag v-if="finding" :type="statusType(finding.status)">{{ finding.status }}</el-tag>
          <span v-if="finding">{{ finding.file_path }}:{{ finding.start_line }}-{{ finding.end_line }}</span>
          <el-tag v-if="finding?.exploit_proven" type="danger">PoC 已证</el-tag>
        </div>
      </div>
      <div class="header-actions">
        <el-dropdown @command="(cmd) => onPatchStatus(cmd)">
          <el-button type="primary">改状态 <el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="in_progress">处理中</el-dropdown-item>
              <el-dropdown-item command="fixed">已修复</el-dropdown-item>
              <el-dropdown-item command="false_positive">误报</el-dropdown-item>
              <el-dropdown-item command="accepted_risk">接受风险</el-dropdown-item>
              <el-dropdown-item command="escalated" divided>升级给客户</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </header>

    <el-row :gutter="16" v-if="finding">
      <el-col :span="14">
        <el-card>
          <template #header>代码片段</template>
          <pre class="code"><code>{{ finding.code_snippet || '// 代码片段不可用' }}</code></pre>
        </el-card>

        <el-card class="mt">
          <template #header>状态变更历史</template>
          <el-timeline>
            <el-timeline-item v-for="h in finding.stateHistory" :key="h.id" :timestamp="h.occurred_at" placement="top">
              <div>
                <el-tag v-if="h.from_status" size="small">{{ h.from_status }}</el-tag>
                <span v-if="h.from_status"> → </span>
                <el-tag :type="statusType(h.to_status)" size="small">{{ h.to_status }}</el-tag>
                <span class="muted">  ({{ h.change_source }}{{ h.reason ? `: ${h.reason}` : '' }})</span>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-card>

        <el-card class="mt">
          <template #header>
            <div class="card-header">
              <span>评论 ({{ finding.comments.length }})</span>
              <el-button size="small" @click="onAiExplain" :loading="aiLoading">AI 解释</el-button>
            </div>
          </template>
          <el-input v-model="newComment" type="textarea" :rows="2" placeholder="写下评论或系统备注..." />
          <el-button type="primary" size="small" @click="onPostComment" :loading="postingComment" class="mt">提交</el-button>
          <div v-if="aiExplanation" class="ai-explanation mt">
            <el-alert type="info" :closable="true" @close="aiExplanation = ''">
              <pre style="white-space: pre-wrap; margin: 0;">{{ aiExplanation }}</pre>
            </el-alert>
          </div>
          <el-divider />
          <div v-for="c in finding.comments" :key="c.id" class="comment">
            <el-tag size="small">{{ c.comment_type }}</el-tag>
            <span class="muted">{{ formatTime(c.created_at) }}</span>
            <div>{{ c.body }}</div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="10">
        <el-card>
          <template #header>漏洞属性</template>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="项目">{{ finding.project_name }}</el-descriptions-item>
            <el-descriptions-item label="客户">{{ finding.customer_name }}</el-descriptions-item>
            <el-descriptions-item label="规则">{{ finding.rule_title }}</el-descriptions-item>
            <el-descriptions-item v-if="finding.cwe_ids?.length" label="CWE">
              <el-tag v-for="c in finding.cwe_ids" :key="c" size="small" class="mr-4">{{ c }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item v-if="finding.owasp_ids?.length" label="OWASP">
              <el-tag v-for="o in finding.owasp_ids" :key="o" size="small" class="mr-4">{{ o }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="首次发现">{{ formatTime(finding.first_seen_at) }}</el-descriptions-item>
            <el-descriptions-item label="最近">{{ formatTime(finding.last_seen_at) }}</el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card class="mt">
          <template #header>PoC 验证记录 ({{ finding.pocRuns.length }})</template>
          <el-empty v-if="!finding.pocRuns.length" description="尚未生成 PoC" />
          <div v-for="p in finding.pocRuns" :key="p.id" class="poc-run">
            <div>
              <el-tag :type="p.exploit_proven ? 'danger' : 'info'" size="small">{{ p.status }}</el-tag>
              <el-tag v-if="p.exploit_proven" type="danger" size="small">已证可利用</el-tag>
              <span class="muted">{{ formatTime(p.created_at) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage } from 'element-plus';
import { ArrowDown } from '@element-plus/icons-vue';
import { apiClient } from '@/api/client';

const route = useRoute();
const id = route.params.id as string;
const loading = ref(false);
const finding = ref<any>(null);
const newComment = ref('');
const postingComment = ref(false);
const aiLoading = ref(false);
const aiExplanation = ref('');

function severityType(s: string) {
  return s === 'critical' ? 'danger' : s === 'high' ? 'warning' : s === 'medium' ? '' : 'info';
}
function statusType(s: string) {
  return s === 'open' ? 'danger' : s === 'in_progress' ? 'warning' : s === 'fixed' ? 'success' : s === 'confirmed' ? 'danger' : 'info';
}
function formatTime(t: string | null) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN', { hour12: false });
}

async function fetchDetail() {
  loading.value = true;
  try {
    const { data } = await apiClient.get(`/provider/v1/findings/${id}`);
    finding.value = data;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '加载失败');
  } finally {
    loading.value = false;
  }
}

async function onPatchStatus(status: string) {
  try {
    await apiClient.patch(`/provider/v1/findings/${id}`, { status, reason: `Provider manual: ${status}` });
    ElMessage.success('状态已更新');
    await fetchDetail();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '更新失败');
  }
}

async function onPostComment() {
  if (!newComment.value.trim()) return;
  postingComment.value = true;
  try {
    await apiClient.post(`/provider/v1/findings/${id}/comments`, { type: 'note', body: newComment.value });
    ElMessage.success('评论已提交');
    newComment.value = '';
    await fetchDetail();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '提交失败');
  } finally {
    postingComment.value = false;
  }
}

async function onAiExplain() {
  aiLoading.value = true;
  try {
    const { data } = await apiClient.post(`/provider/v1/findings/${id}/ai-explain`);
    aiExplanation.value = `${data.explanation}\n\n[${data.aiBypassed ? '规则模板(P4.1 后接 LLM)' : 'LLM 解释'}]`;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? 'AI 解释失败');
  } finally {
    aiLoading.value = false;
  }
}

onMounted(fetchDetail);
</script>

<style scoped>
.finding-detail { padding: 24px; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
.page-header h2 { margin: 8px 0; }
.meta { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; color: var(--color-text-secondary); font-size: 13px; }
.header-actions { display: flex; gap: 8px; }
.mt { margin-top: 16px; }
.muted { color: var(--color-text-secondary); font-size: 12px; }
.code { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 13px; line-height: 1.5; overflow-x: auto; max-height: 400px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.ai-explanation pre { font-family: var(--font-mono); font-size: 13px; }
.comment { padding: 8px 0; border-bottom: 1px solid var(--color-border-soft); }
.comment:last-child { border-bottom: none; }
.poc-run { padding: 8px 0; border-bottom: 1px solid var(--color-border-soft); }
.poc-run:last-child { border-bottom: none; }
.mr-4 { margin-right: 4px; }
</style>
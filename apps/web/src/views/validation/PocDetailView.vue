<template>
  <div class="poc-detail" v-loading="store.loading">
    <header class="page-header">
      <el-button link @click="goBack">
        <el-icon><ArrowLeft /></el-icon> 返回队列
      </el-button>
      <h2>{{ poc?.finding.title ?? '加载中...' }}</h2>
      <div class="meta">
        <el-tag :type="severityColor(poc?.finding.severity)">{{ poc?.finding.severity }}</el-tag>
        <span class="file">{{ poc?.finding.file }}:{{ poc?.finding.line }}</span>
        <el-tag :type="statusColor(poc?.status)">{{ statusLabel(poc?.status) }}</el-tag>
        <el-tag v-if="poc?.exploitProven" type="success" effect="dark">✓ 已证可利用</el-tag>
      </div>
    </header>

    <el-row :gutter="20">
      <el-col :span="14">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>PoC 脚本</span>
              <div class="actions">
                <el-button size="small" @click="copyScript" :icon="DocumentCopy">复制</el-button>
                <el-button size="small" @click="showAddToLibrary = true" :icon="FolderAdd" :disabled="!canSaveToLibrary">入库</el-button>
              </div>
            </div>
          </template>
          <pre class="code-block"><code>{{ poc?.pocScript }}</code></pre>
        </el-card>

        <el-card v-if="poc?.stdoutLog || poc?.stderrLog" class="mt">
          <template #header>沙箱执行日志</template>
          <el-tabs v-model="activeLog">
            <el-tab-pane label="stdout" name="stdout">
              <pre class="code-block"><code>{{ poc?.stdoutLog || '(无输出)' }}</code></pre>
            </el-tab-pane>
            <el-tab-pane label="stderr" name="stderr">
              <pre class="code-block"><code>{{ poc?.stderrLog || '(无输出)' }}</code></pre>
            </el-tab-pane>
          </el-tabs>
        </el-card>

        <el-card v-if="poc?.behaviorReport" class="mt">
          <template #header>行为分析</template>
          <el-descriptions :column="2" border>
            <el-descriptions-item label="执行时长">{{ poc?.behaviorReport.durationMs }}ms</el-descriptions-item>
            <el-descriptions-item label="网络调用">
              <el-tag v-for="(nc, i) in poc?.behaviorReport.networkCalls ?? []" :key="i" size="small" type="info" class="mr">
                {{ nc }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="系统调用" :span="2">
              <ul class="action-list">
                <li v-for="(a, i) in poc?.behaviorReport.actions ?? []" :key="i">{{ a }}</li>
              </ul>
            </el-descriptions-item>
            <el-descriptions-item label="访问文件" :span="2">
              <code v-for="(f, i) in poc?.behaviorReport.filesAccessed ?? []" :key="i" class="file-tag">{{ f }}</code>
            </el-descriptions-item>
          </el-descriptions>
          <el-alert v-if="poc?.evidenceSummary" :type="poc.exploitProven ? 'success' : 'warning'" :title="poc.evidenceSummary" :closable="false" show-icon class="mt" />
        </el-card>
      </el-col>

      <el-col :span="10">
        <el-card>
          <template #header>操作</template>
          <div class="action-stack">
            <el-button v-if="canApprove" type="primary" @click="onApprove" :icon="Check">批准执行</el-button>
            <el-button v-if="canExecute" type="success" :loading="store.executing" @click="onExecute" :icon="VideoPlay">在沙箱执行</el-button>
            <el-button v-if="canReject" type="danger" plain @click="showReject = true" :icon="Close">驳回</el-button>
            <el-button v-if="canSaveToLibrary" @click="showAddToLibrary = true" :icon="FolderAdd">存入 PoC 库</el-button>
          </div>
        </el-card>

        <el-card class="mt">
          <template #header>AI 对话</template>
          <div class="chat-list">
            <div v-for="m in store.chatMessages" :key="m.id" :class="['chat-msg', m.role]">
              <el-avatar :size="28" :style="{ background: m.role === 'user' ? '#4F46E5' : '#10B981' }">
                {{ m.role === 'user' ? '我' : 'AI' }}
              </el-avatar>
              <div class="chat-content">{{ m.content }}</div>
            </div>
            <el-empty v-if="!store.chatMessages.length" description="无对话" :image-size="60" />
          </div>
          <el-input v-model="chatInput" type="textarea" :rows="2" placeholder="问 AI: 这个 PoC 怎么简化? / 为什么这样写? / 是否安全?" />
          <el-button type="primary" class="mt" :disabled="!chatInput.trim()" @click="onSendChat" :icon="Promotion">发送</el-button>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog v-model="showReject" title="驳回 PoC" width="480">
      <el-form>
        <el-form-item label="驳回原因" required>
          <el-input v-model="rejectReason" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showReject = false">取消</el-button>
        <el-button type="danger" @click="onReject" :disabled="!rejectReason.trim()">确认驳回</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showAddToLibrary" title="加入 PoC 库" width="480">
      <el-form>
        <el-form-item label="标题" required>
          <el-input v-model="libTitle" placeholder="如: SQL 注入 - 时间盲注" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="libDescription" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddToLibrary = false">取消</el-button>
        <el-button type="primary" @click="onSaveLibrary" :disabled="!libTitle.trim()">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import {
  ArrowLeft, Check, Close, VideoPlay, DocumentCopy, FolderAdd, Promotion,
} from '@element-plus/icons-vue';
import { useValidationStore } from '@/stores/validation';

const route = useRoute();
const router = useRouter();
const store = useValidationStore();

const activeLog = ref('stdout');
const chatInput = ref('');
const showReject = ref(false);
const rejectReason = ref('');
const showAddToLibrary = ref(false);
const libTitle = ref('');
const libDescription = ref('');

const poc = computed(() => store.currentPoc);
const canApprove = computed(() => poc.value?.status === 'pending');
const canExecute = computed(() => poc.value?.status === 'approved');
const canReject = computed(() => poc.value && ['pending', 'approved'].includes(poc.value.status));
const canSaveToLibrary = computed(() => poc.value && ['success', 'failed'].includes(poc.value.status));

function statusLabel(s?: string) {
  if (!s) return '';
  return ({ pending: '待审', approved: '已批准', running: '运行中', success: '已成功', failed: '已失败', timeout: '超时', canceled: '已取消' } as Record<string, string>)[s] ?? s;
}

function statusColor(s?: string): '' | 'success' | 'warning' | 'info' | 'danger' | 'primary' {
  if (!s) return 'info';
  return ({ pending: 'info', approved: 'primary', running: 'warning', success: 'success', failed: 'danger', timeout: 'warning', canceled: 'info' } as Record<string, '' | 'success' | 'warning' | 'info' | 'danger' | 'primary'>)[s] ?? 'info';
}

function severityColor(s?: string): '' | 'danger' | 'warning' | 'info' | 'primary' {
  if (!s) return 'info';
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'info';
}

function goBack() {
  router.push('/validation');
}

async function copyScript() {
  if (!poc.value) return;
  try {
    await navigator.clipboard.writeText(poc.value.pocScript);
    ElMessage.success('已复制 PoC 脚本');
  } catch {
    ElMessage.error('复制失败');
  }
}

async function onApprove() {
  if (!poc.value) return;
  try {
    await store.approve(poc.value.id);
    ElMessage.success('已批准');
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '批准失败');
  }
}

async function onReject() {
  if (!poc.value || !rejectReason.value.trim()) return;
  try {
    await store.reject(poc.value.id, rejectReason.value.trim());
    showReject.value = false;
    rejectReason.value = '';
    ElMessage.success('已驳回');
    goBack();
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '驳回失败');
  }
}

async function onExecute() {
  if (!poc.value) return;
  try {
    const result = await store.execute(poc.value.id);
    ElMessage.success(`执行 ${result?.exploitProven ? '成功(已证可利用)' : '完成'}`);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '执行失败');
  }
}

async function onSendChat() {
  if (!poc.value || !chatInput.value.trim()) return;
  const msg = chatInput.value.trim();
  chatInput.value = '';
  try {
    await store.sendMessage(poc.value.id, msg);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '发送失败');
  }
}

async function onSaveLibrary() {
  if (!poc.value || !libTitle.value.trim()) return;
  try {
    await store.saveToLibrary(poc.value.id, libTitle.value.trim(), libDescription.value.trim() || undefined);
    showAddToLibrary.value = false;
    libTitle.value = '';
    libDescription.value = '';
    ElMessage.success('已加入 PoC 库');
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '保存失败');
  }
}

onMounted(async () => {
  const id = route.params.id as string;
  await store.fetchPoc(id);
  await store.fetchChat(id);
});
</script>

<style scoped>
.poc-detail { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 8px 0; font-size: 18px; }
.page-header .meta { display: flex; align-items: center; gap: 8px; }
.page-header .file { font-family: var(--font-mono); font-size: 12px; color: var(--color-text-secondary); }
.card-header { display: flex; align-items: center; justify-content: space-between; }
.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 12px;
  overflow-x: auto;
  max-height: 480px;
}
.code-block code { color: inherit; }
.action-stack { display: flex; flex-direction: column; gap: 8px; }
.action-stack .el-button { width: 100%; justify-content: center; }
.chat-list { max-height: 360px; overflow-y: auto; padding: 8px 0; }
.chat-msg { display: flex; gap: 12px; margin-bottom: 12px; }
.chat-msg.user { flex-direction: row-reverse; }
.chat-msg .chat-content {
  background: var(--color-bg-base);
  padding: 8px 12px;
  border-radius: 6px;
  max-width: 80%;
  white-space: pre-wrap;
  font-size: 13px;
}
.chat-msg.assistant .chat-content { background: #ECFDF5; }
.mt { margin-top: 16px; }
.mr { margin-right: 4px; }
.action-list { margin: 0; padding-left: 20px; }
.action-list li { font-size: 13px; margin: 2px 0; }
.file-tag { background: #F3F4F6; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-right: 4px; }
</style>

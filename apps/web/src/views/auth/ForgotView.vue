<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>忘记密码</h1>
      <p class="subtitle">输入注册邮箱,我们会发送重置链接</p>
      <el-form :model="form" label-width="0" @submit.prevent>
        <el-form-item>
          <el-input v-model="form.email" type="email" placeholder="邮箱" size="large" />
        </el-form-item>
        <el-button type="primary" size="large" :loading="loading" @click="onSubmit" class="full">发送重置链接</el-button>
      </el-form>
      <div v-if="message" class="mt">
        <el-alert :type="sent ? 'success' : 'info'" :closable="false">{{ message }}</el-alert>
        <div v-if="devToken" class="dev-token">
          <strong>开发环境提示</strong>:复制此 token 到 <code>/reset?token=...</code>
          <el-input v-model="devToken" readonly type="textarea" :rows="2" />
        </div>
      </div>
      <el-link @click="$router.push('/login')" class="mt back-link">返回登录</el-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { apiClient } from '@/api/client';

const router = useRouter();
const form = reactive({ email: '' });
const loading = ref(false);
const sent = ref(false);
const message = ref('');
const devToken = ref('');

async function onSubmit() {
  if (!form.email) { ElMessage.warning('请输入邮箱'); return; }
  loading.value = true;
  try {
    const { data } = await apiClient.post('/api/auth/forgot', { email: form.email });
    sent.value = data.ok ?? true;
    message.value = data.message ?? '重置链接已发送';
    if (data.devToken) devToken.value = data.devToken;
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '提交失败');
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.auth-page { min-height: 100vh; background: linear-gradient(135deg, #667eea, #764ba2); display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
.auth-card { background: white; border-radius: 12px; padding: 48px; max-width: 420px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.1); }
.auth-card h1 { margin: 0 0 8px; font-size: 22px; }
.subtitle { color: #6b7280; margin: 0 0 24px; }
.full { width: 100%; }
.mt { margin-top: 16px; }
.back-link { display: block; text-align: center; }
.dev-token { font-size: 12px; color: #92400e; background: #fef3c7; padding: 8px; border-radius: 4px; }
</style>
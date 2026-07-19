<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>重置密码</h1>
      <p class="subtitle">设置新密码(至少 10 位)</p>
      <el-form :model="form" label-width="0">
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="新密码" show-password size="large" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.confirm" type="password" placeholder="确认新密码" show-password size="large" />
        </el-form-item>
        <el-button type="primary" size="large" :loading="loading" @click="onSubmit" class="full">重置密码</el-button>
      </el-form>
      <el-link @click="$router.push('/login')" class="mt back-link">返回登录</el-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { apiClient } from '@/api/client';

const route = useRoute();
const router = useRouter();
const token = ref('');
const form = reactive({ password: '', confirm: '' });
const loading = ref(false);

onMounted(() => {
  const t = route.query.token;
  if (typeof t === 'string' && t.length >= 32) token.value = t;
  else ElMessage.error('Token 无效或缺失');
});

async function onSubmit() {
  if (form.password.length < 10) { ElMessage.warning('密码至少 10 位'); return; }
  if (form.password !== form.confirm) { ElMessage.warning('两次密码不一致'); return; }
  if (!token.value) return;
  loading.value = true;
  try {
    const { data } = await apiClient.post('/api/auth/reset', { token: token.value, newPassword: form.password });
    ElMessage.success(data.message);
    setTimeout(() => router.push('/login'), 1500);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '重置失败');
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
</style>
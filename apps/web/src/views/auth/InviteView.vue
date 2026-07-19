<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>接受邀请</h1>
      <p class="subtitle">设置您的账号信息</p>
      <el-form :model="form" label-width="100">
        <el-form-item label="姓名"><el-input v-model="form.fullName" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="form.password" type="password" show-password /></el-form-item>
        <el-form-item label="确认密码"><el-input v-model="form.confirm" type="password" show-password /></el-form-item>
        <el-button type="primary" size="large" :loading="loading" @click="onSubmit" class="full">激活账号</el-button>
      </el-form>
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
const form = reactive({ fullName: '', password: '', confirm: '' });
const loading = ref(false);

onMounted(() => {
  const t = route.query.token ?? route.path.split('/').pop();
  if (typeof t === 'string' && t.length >= 32) token.value = t;
  else ElMessage.error('邀请 Token 无效');
});

async function onSubmit() {
  if (!form.fullName) { ElMessage.warning('请输入姓名'); return; }
  if (form.password.length < 10) { ElMessage.warning('密码至少 10 位'); return; }
  if (form.password !== form.confirm) { ElMessage.warning('两次密码不一致'); return; }
  if (!token.value) return;
  loading.value = true;
  try {
    const { data } = await apiClient.post(`/api/auth/invite/${token.value}/accept`, form);
    ElMessage.success(data.message);
    setTimeout(() => router.push('/login'), 1500);
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error?.message ?? '激活失败');
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.auth-page { min-height: 100vh; background: linear-gradient(135deg, #667eea, #764ba2); display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
.auth-card { background: white; border-radius: 12px; padding: 48px; max-width: 480px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.1); }
.auth-card h1 { margin: 0 0 8px; font-size: 22px; }
.subtitle { color: #6b7280; margin: 0 0 24px; }
.full { width: 100%; margin-top: 8px; }
</style>
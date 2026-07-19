<template>
  <div class="login-page">
    <el-card class="login-card">
      <div class="brand">
        <h1>security-vule</h1>
        <p class="subtitle">MSSP 白盒漏洞挖掘与 PoC 验证平台</p>
      </div>
      <el-form :model="form" :rules="rules" ref="formRef" label-position="top" autocomplete="off" @submit.prevent="onSubmit">
        <!-- 隐藏伪字段：欺骗浏览器密码管理器，阻止自动填充和保存提示 -->
        <input type="text" name="fake-username" style="display:none" autocomplete="username" aria-hidden="true" tabindex="-1" />
        <input type="password" name="fake-password" style="display:none" autocomplete="current-password" aria-hidden="true" tabindex="-1" />
        <el-form-item label="邮箱" prop="email">
          <el-input v-model="form.email" placeholder="请输入邮箱" :prefix-icon="User" autocomplete="off" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" show-password placeholder="请输入密码" :prefix-icon="Lock" autocomplete="new-password" @keyup.enter="onSubmit" />
        </el-form-item>
        <el-button type="primary" :loading="loading" class="login-btn" @click="onSubmit">
          登录
        </el-button>
      </el-form>
      <el-divider>或</el-divider>
      <el-button type="primary" plain class="sso-btn" :icon="Promotion" @click="onSsoLogin">
        使用企业 SSO 登录
      </el-button>
      <p class="sso-hint">SP-initiated SAML 2.0 · 自动从 IdP JIT 创建账号</p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { ElMessage, type FormInstance, type FormRules } from 'element-plus';
import { User, Lock } from '@element-plus/icons-vue';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const formRef = ref<FormInstance>();
const loading = ref(false);
const form = reactive({ email: '', password: '' });

const rules: FormRules = {
  email: [{ required: true, message: '请输入邮箱', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
};

async function onSubmit() {
  if (!formRef.value) return;
  await formRef.value.validate(async (valid) => {
    if (!valid) return;
    loading.value = true;
    try {
      await auth.login(form.email, form.password);
      const portal = auth.user?.portal;
      const target = (route.query.redirect as string) || (portal === 'customer' ? '/portal' : '/');
      router.push(target);
    } catch (err: any) {
      ElMessage.error(err.response?.data?.error?.message || '登录失败');
    } finally {
      loading.value = false;
    }
  });
}

function onSsoLogin() {
  const tenantId = '00000000-0000-0000-0000-000000000001';
  const relayState = (route.query.redirect as string) || '/';
  window.location.href = `/api/auth/sso/login?tenant_id=${tenantId}&relay_state=${encodeURIComponent(relayState)}`;
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #EEF2FF 0%, #F0F9FF 100%);
}
.login-card { width: 420px; padding: 8px; }
.brand { text-align: center; margin-bottom: 24px; }
.brand h1 { font-size: 24px; margin: 0 0 8px; color: var(--color-primary); }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.login-btn { width: 100%; margin-top: 8px; }
</style>

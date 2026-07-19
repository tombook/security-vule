<template>
  <div class="callback-page">
    <el-result v-if="error" icon="error" :title="errorTitle" :sub-title="error">
      <template #extra>
        <el-button @click="goLogin">返回登录</el-button>
      </template>
    </el-result>
    <el-result v-else-if="ready" icon="success" title="SSO 登录成功" sub-title="正在跳转...">
    </el-result>
    <el-result v-else icon="info" title="处理 SSO 回调" sub-title="正在校验 SAML 断言...">
      <template #extra>
        <el-progress :percentage="66" :indeterminate="true" />
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { useAuthStore } from '@/stores/auth';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

const error = ref('');
const ready = ref(false);

const errorTitle = computed(() => {
  if (route.query.reason === 'signature_verification_failed') return 'SAML 签名验证失败';
  if (route.query.reason === 'tenant_not_found') return '租户未配置 SSO';
  if (route.query.reason === 'invalid_response') return 'SAML 响应无效';
  if (route.query.reason === 'no_email') return 'IdP 未返回邮箱';
  return 'SSO 登录失败';
});

async function processCallback() {
  const hash = window.location.hash.replace(/^#/, '');
  const params = new URLSearchParams(hash);
  const accessToken = params.get('access_token');
  const relayState = params.get('relay_state') || '/';

  if (!accessToken) {
    error.value = 'No access token in callback';
    return;
  }
  try {
    localStorage.setItem('access_token', accessToken);
    await auth.fetchMe();
    ready.value = true;
    const portal = auth.user?.portal;
    const target = relayState || (portal === 'customer' ? '/portal' : '/');
    setTimeout(() => router.push(target), 1000);
  } catch (err: any) {
    error.value = err.message ?? 'Failed to process SSO callback';
    ElMessage.error(error.value);
  }
}

function goLogin() {
  router.push('/login');
}

onMounted(processCallback);
</script>

<style scoped>
.callback-page { max-width: 720px; margin: 60px auto; }
</style>

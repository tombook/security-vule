<template>
  <div class="sso-error-page">
    <el-result icon="error" :title="errorTitle" :sub-title="errorReason">
      <template #extra>
        <el-button type="primary" @click="$router.push('/login')">返回登录</el-button>
        <el-button @click="$router.push('/')">回工作台</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';

const route = useRoute();
const errorReason = computed(() => (route.query.reason as string) ?? 'unknown');
const errorTitle = computed(() => {
  const r = route.query.reason as string;
  if (r === 'signature_verification_failed') return 'SAML 签名验证失败';
  if (r === 'tenant_not_found') return '租户未配置 SSO';
  if (r === 'invalid_response') return 'SAML 响应无效';
  if (r === 'no_email') return 'IdP 未返回邮箱';
  return 'SSO 错误';
});
</script>

<style scoped>
.sso-error-page { max-width: 720px; margin: 60px auto; }
</style>

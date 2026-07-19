<template>
  <div class="oauth-callback">
    <el-result :icon="icon" :title="title" :sub-title="subTitle">
      <template #extra>
        <el-button @click="$router.push('/')">回工作台</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { apiClient } from '@/api/client';
import { ElMessage } from 'element-plus';

const route = useRoute();
const router = useRouter();
const icon = ref<any>('info');
const title = ref('正在处理...');
const subTitle = ref('正在用 GitHub/GitLab 返回的 code 换取 Token');

onMounted(async () => {
  const params = route.query as Record<string, string>;
  if (params.error) {
    icon.value = 'error';
    title.value = 'OAuth 失败';
    subTitle.value = `错误: ${params.error_description ?? params.error}`;
    return;
  }
  if (!params.code || !params.state) {
    icon.value = 'error';
    title.value = '回调参数缺失';
    subTitle.value = '缺少 code 或 state 参数';
    return;
  }

  const provider = window.location.pathname.includes('gitlab') ? 'gitlab' : 'github';
  try {
    const { data } = await apiClient.post('/provider/v1/oauth/connect/callback', {
      provider,
      code: params.code,
      state: params.state,
    });
    icon.value = 'success';
    title.value = '代码源已连接!';
    subTitle.value = `已连接 ${data.source.source_type}: ${data.source.repo_full_name ?? '上传型'}`;

    setTimeout(() => {
      const target = data.redirectAfter ?? '/';
      router.push(target.startsWith('/') ? target : `/${target}`);
    }, 2000);
  } catch (err: any) {
    icon.value = 'error';
    title.value = 'Token 兑换失败';
    subTitle.value = err.response?.data?.error?.message ?? '未知错误';
  }
});
</script>

<style scoped>
.oauth-callback { max-width: 600px; margin: 80px auto; }
</style>
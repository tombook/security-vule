<template>
  <div class="header-content">
    <div class="header-left">
      <span class="page-title">{{ route.meta.title || 'MSSP 平台' }}</span>
    </div>
    <div class="header-right">
      <el-badge :value="0" :max="99" class="notification-icon">
        <el-icon :size="20"><Bell /></el-icon>
      </el-badge>
      <el-dropdown @command="handleCommand">
        <span class="user-menu">
          <el-icon><UserFilled /></el-icon>
          {{ auth.user?.full_name || auth.user?.email || '未登录' }}
          <el-icon><CaretBottom /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item v-if="auth.user?.portal === 'customer'" command="goto-portal">客户门户</el-dropdown-item>
            <el-dropdown-item command="logout">退出登录</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

function handleCommand(cmd: string) {
  if (cmd === 'logout') {
    auth.logout();
    router.push('/login');
  } else if (cmd === 'goto-portal') {
    router.push('/portal');
  }
}
</script>

<style scoped>
.header-content { display: flex; align-items: center; justify-content: space-between; width: 100%; }
.page-title { font-size: 16px; font-weight: 600; color: var(--color-text-primary); }
.header-right { display: flex; align-items: center; gap: 24px; }
.user-menu { display: flex; align-items: center; gap: 6px; cursor: pointer; color: var(--color-text-primary); }
.notification-icon { display: flex; align-items: center; }
</style>

<template>
  <div class="portal-shell">
    <el-aside :width="sidebarWidth" class="portal-sidebar">
      <div class="brand">
        <h2>security-vule</h2>
        <p class="subtitle">客户门户</p>
      </div>
      <el-menu
        :default-active="route.path"
        router
        background-color="#1e3a5f"
        text-color="#cbd5e1"
        active-text-color="#fff"
      >
        <el-menu-item index="/portal">
          <el-icon><Monitor /></el-icon><span>首页</span>
        </el-menu-item>
        <el-menu-item index="/portal/projects">
          <el-icon><Folder /></el-icon><span>项目</span>
        </el-menu-item>
        <el-menu-item index="/portal/findings">
          <el-icon><Warning /></el-icon><span>漏洞</span>
        </el-menu-item>
        <el-menu-item index="/portal/reports">
          <el-icon><Document /></el-icon><span>报告</span>
        </el-menu-item>
        <el-menu-item index="/portal/usage">
          <el-icon><DataLine /></el-icon><span>用量</span>
        </el-menu-item>
        <el-menu-item index="/portal/settings">
          <el-icon><Setting /></el-icon><span>设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="portal-header">
        <span class="page-title">{{ route.meta.title || '客户门户' }}</span>
        <el-dropdown @command="handleCommand">
          <span class="user-menu">
            <el-icon><UserFilled /></el-icon>
            {{ auth.user?.full_name || auth.user?.email || '客户用户' }}
            <el-tag v-if="auth.user?.role" size="small" type="primary" class="role-tag">{{ auth.user?.role }}</el-tag>
            <el-icon><CaretBottom /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="portal-main">
        <router-view />
      </el-main>
    </el-container>
  </div>
</template>

<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router';
import { Monitor, Folder, Warning, Document, DataLine, Setting, UserFilled, CaretBottom } from '@element-plus/icons-vue';
import { useAuthStore } from '@/stores/auth';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const sidebarWidth = '220px';

function handleCommand(cmd: string) {
  if (cmd === 'logout') {
    auth.logout();
    router.push('/login');
  }
}
</script>

<style scoped>
.portal-shell { height: 100vh; }
.portal-sidebar { background: var(--color-bg-1); color: var(--color-text-1); border-right: 1px solid var(--color-border-soft); }
.brand { padding: 20px 16px 16px; border-bottom: 1px solid var(--color-border-soft); }
.brand h2 { color: var(--color-text-1); font-size: 18px; margin: 0; font-weight: 600; }
.subtitle { color: var(--color-text-3); font-size: 12px; margin: 4px 0 0; }
:deep(.el-menu) { border-right: 0; }
.portal-header {
  background: var(--color-bg-1);
  border-bottom: 1px solid var(--color-border-soft);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px;
  box-shadow: var(--shadow-sm);
}
.page-title { font-size: 16px; font-weight: 600; color: var(--color-text-1); }
.user-menu { display: flex; align-items: center; gap: 6px; cursor: pointer; }
.role-tag { margin-left: 4px; }
.portal-main { background: var(--color-bg-2); padding: 24px; }
@media (max-width: 768px) {
  .portal-sidebar { display: none; }
  .portal-main { padding: var(--space-3); }
}
</style>

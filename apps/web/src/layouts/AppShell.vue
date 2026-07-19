<template>
  <el-container class="app-shell">
    <el-aside :width="sidebarWidth" class="app-sidebar">
      <AppSidebar />
    </el-aside>
    <el-container>
      <el-header class="app-header">
        <AppHeader />
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import AppSidebar from '@/components/AppSidebar.vue';
import AppHeader from '@/components/AppHeader.vue';
const sidebarWidth = '220px';
</script>

<style scoped>
.app-shell { height: 100vh; }
.app-sidebar { background: var(--color-bg-1); color: var(--color-text-1); border-right: 1px solid var(--color-border-soft); }
.app-header {
  background: var(--color-bg-1);
  border-bottom: 1px solid var(--color-border-soft);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px;
  box-shadow: var(--shadow-sm);
}
.app-main { background: var(--color-bg-2); padding: 24px; }
@media (max-width: 768px) {
  .app-sidebar { display: none; }
  .app-main { padding: var(--space-3); }
}
</style>

<template>
  <div class="app-brand">
    <h2>security-vule</h2>
    <p class="subtitle">MSSP 白盒漏洞平台</p>
  </div>
  <el-menu
    :default-active="route.path"
    router
    background-color="var(--color-bg-1)"
    text-color="var(--color-text-2)"
    active-text-color="var(--color-primary)"
  >
    <el-menu-item index="/">
      <el-icon><Monitor /></el-icon><span>工作台</span>
    </el-menu-item>

    <!-- ── 安全评估流程（按业务顺序排列）────────────── -->
    <!-- Step 1: 客户管理 — 业务入口 -->
    <el-menu-item-group title="安全评估">
      <el-menu-item index="/customers">
        <el-icon><User /></el-icon><span>① 客户</span>
      </el-menu-item>
      <!-- Step 2: 代码源 — 多租户检测项目汇总列表 -->
      <el-menu-item index="/sources">
        <el-icon><Files /></el-icon><span>② 代码源</span>
      </el-menu-item>
      <!-- Step 3: 目标管理 — 每个项目沙盒使用 + 认证方式管理 -->
      <el-menu-item index="/targets">
        <el-icon><Aim /></el-icon><span>③ 目标管理</span>
      </el-menu-item>
      <!-- Step 4: 检测中心 — 项目各类检测能力的分类与配置 -->
      <el-menu-item index="/detection">
        <el-icon><Cpu /></el-icon><span>④ 检测中心</span>
      </el-menu-item>
      <!-- Step 5: PoC 验证 — 每个项目检测任务调度管理与状态 -->
      <el-menu-item index="/validation">
        <el-icon><CircleCheck /></el-icon><span>⑤ PoC 验证</span>
      </el-menu-item>
      <!-- Step 6: 漏洞 — 客户+项目+漏洞 汇总统计列表 -->
      <el-menu-item index="/findings">
        <el-icon><Warning /></el-icon><span>⑥ 漏洞</span>
      </el-menu-item>
    </el-menu-item-group>

    <!-- ── 管理功能区 ──────────────────────────────── -->
    <el-menu-item-group title="管理">
      <el-menu-item index="/billing">
        <el-icon><Money /></el-icon><span>计费</span>
      </el-menu-item>
      <el-menu-item index="/governance">
        <el-icon><Lock /></el-icon><span>治理</span>
      </el-menu-item>
      <el-menu-item index="/settings">
        <el-icon><Setting /></el-icon><span>设置</span>
      </el-menu-item>
    </el-menu-item-group>
  </el-menu>
</template>

<script setup lang="ts">
import { useRoute } from 'vue-router';
import { Monitor, Cpu, CircleCheck, Money, Lock, Setting, Warning, Files, Aim, User } from '@element-plus/icons-vue';
const route = useRoute();
</script>

<style scoped>
.app-brand { padding: 20px 16px 16px; border-bottom: 1px solid var(--color-border-soft); }
.app-brand h2 { color: var(--color-text-1); font-size: 18px; margin: 0; font-weight: 600; }
.subtitle { color: var(--color-text-3); font-size: 12px; margin: 4px 0 0; }
:deep(.el-menu) { border-right: 0; }
:deep(.el-menu-item.is-active) { background: var(--color-primary-soft) !important; border-radius: 0 var(--radius-md) var(--radius-md) 0; }
:deep(.el-menu-item-group__title) { font-size: 11px; color: var(--color-text-placeholder); padding: 12px 16px 4px; text-transform: uppercase; letter-spacing: 0.5px; }
</style>
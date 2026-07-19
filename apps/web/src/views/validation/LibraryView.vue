<template>
  <div class="library-page" v-loading="store.loading">
    <header class="page-header">
      <h2>PoC 库</h2>
      <p class="subtitle">已验证的 PoC 沉淀 · 按 CWE 复用 · 提升下次验证速度</p>
    </header>

    <el-row :gutter="16">
      <el-col v-for="item in store.library" :key="item.id" :xs="24" :sm="12" :md="8" :lg="6">
        <el-card class="lib-card" shadow="hover">
          <div class="lib-header">
            <el-icon :size="24" color="#4F46E5"><CollectionTag /></el-icon>
            <span class="lib-title">{{ item.title }}</span>
          </div>
          <p class="lib-desc">{{ item.description || '无描述' }}</p>
          <div class="lib-tags">
            <el-tag v-for="cwe in item.cwe_ids" :key="cwe" size="small" type="info" class="lib-tag">{{ cwe }}</el-tag>
            <el-tag v-for="fw in item.framework_tags" :key="fw" size="small" type="success" class="lib-tag">{{ fw }}</el-tag>
          </div>
          <div class="lib-footer">
            <span class="reuse-count">↻ 复用 {{ item.reuse_count }} 次</span>
            <span class="lib-date">{{ formatDate(item.created_at) }}</span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-empty v-if="!store.loading && store.library.length === 0" description="PoC 库为空" />
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue';
import { CollectionTag } from '@element-plus/icons-vue';
import { useValidationStore } from '@/stores/validation';

const store = useValidationStore();

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('zh-CN');
}

onMounted(() => store.fetchLibrary());
</script>

<style scoped>
.library-page { display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: var(--color-text-secondary); font-size: 13px; margin: 0; }
.lib-card { margin-bottom: 16px; height: 100%; }
.lib-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.lib-title { font-weight: 600; font-size: 14px; }
.lib-desc { color: var(--color-text-secondary); font-size: 12px; min-height: 32px; margin: 0 0 12px; }
.lib-tags { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }
.lib-tag { font-size: 10px; }
.lib-footer { display: flex; justify-content: space-between; font-size: 11px; color: var(--color-text-secondary); padding-top: 8px; border-top: 1px solid var(--color-border-light); }
.reuse-count { color: #4F46E5; font-weight: 500; }
</style>

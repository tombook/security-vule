<template>
  <div class="apply-page">
    <div class="apply-card">
      <h1>申请成为服务商</h1>
      <p class="subtitle">security-vule MSSP 平台 · 申请审核通过后将开通租户</p>
      <el-form :model="form" :rules="rules" ref="formRef" label-width="120">
        <el-form-item label="公司名" prop="companyName">
          <el-input v-model="form.companyName" placeholder="例:阿里安全" />
        </el-form-item>
        <el-form-item label="联系人" prop="contactName">
          <el-input v-model="form.contactName" />
        </el-form-item>
        <el-form-item label="联系邮箱" prop="contactEmail">
          <el-input v-model="form.contactEmail" type="email" />
        </el-form-item>
        <el-form-item label="联系电话">
          <el-input v-model="form.contactPhone" />
        </el-form-item>
        <el-form-item label="服务规模">
          <el-select v-model="form.serviceScale" placeholder="请选择" style="width: 100%">
            <el-option label="1-10 人" value="1-10" />
            <el-option label="10-50 人" value="10-50" />
            <el-option label="50-200 人" value="50-200" />
            <el-option label="200+ 人" value="200+" />
          </el-select>
        </el-form-item>
        <el-form-item label="客户量级">
          <el-select v-model="form.customerVolume" placeholder="请选择" style="width: 100%">
            <el-option label="1-5 客户" value="1-5" />
            <el-option label="5-20 客户" value="5-20" />
            <el-option label="20-100 客户" value="20-100" />
            <el-option label="100+ 客户" value="100+" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="onSubmit">提交申请</el-button>
          <el-button @click="$router.push('/login')">返回登录</el-button>
        </el-form-item>
      </el-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, type FormInstance, type FormRules } from 'element-plus';
import { apiClient } from '@/api/client';

const router = useRouter();
const formRef = ref<FormInstance>();
const loading = ref(false);
const form = reactive({
  companyName: '',
  contactName: '',
  contactEmail: '',
  contactPhone: '',
  serviceScale: '',
  customerVolume: '',
});

const rules: FormRules = {
  companyName: [{ required: true, min: 2, max: 200, message: '请输入公司名' }],
  contactName: [{ required: true, message: '请输入联系人' }],
  contactEmail: [{ required: true, type: 'email', message: '请输入有效邮箱' }],
};

async function onSubmit() {
  if (!formRef.value) return;
  await formRef.value.validate(async (valid) => {
    if (!valid) return;
    loading.value = true;
    try {
      await apiClient.post('/api/onboarding/apply', form);
      ElMessage.success('申请已提交,平台运营将在 1-2 个工作日内审核');
      setTimeout(() => router.push('/login'), 1500);
    } catch (err: any) {
      ElMessage.error(err.response?.data?.error?.message ?? '提交失败');
    } finally {
      loading.value = false;
    }
  });
}
</script>

<style scoped>
.apply-page { min-height: 100vh; background: linear-gradient(135deg, #667eea, #764ba2); display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
.apply-card { background: white; border-radius: 12px; padding: 48px; max-width: 600px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.1); }
.apply-card h1 { margin: 0 0 8px; font-size: 24px; }
.subtitle { color: #6b7280; margin: 0 0 32px; }
</style>
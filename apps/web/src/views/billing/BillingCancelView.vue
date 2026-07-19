<template>
  <div class="cancel-page">
    <el-result icon="info" title="已取消结账" sub-title="您可以随时回来升级套餐">
      <template #extra>
        <el-button type="primary" @click="$router.push('/billing')">返回计费</el-button>
      </template>
    </el-result>
  </div>
</template>

<style scoped>
.cancel-page { max-width: 720px; margin: 40px auto; }
</style>

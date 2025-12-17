<template>
  <div class="not-found">
    <el-empty description="頁面不存在">
      <el-button type="primary" @click="router.push('/')">返回首頁</el-button>
    </el-empty>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<style lang="scss" scoped>
.not-found {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>

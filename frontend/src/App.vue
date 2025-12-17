<template>
  <el-config-provider :locale="zhTw">
    <router-view />
  </el-config-provider>
</template>

<script setup>
import zhTw from 'element-plus/es/locale/lang/zh-tw'
</script>

<style>
#app {
  min-height: 100vh;
}
</style>

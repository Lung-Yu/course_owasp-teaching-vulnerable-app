<template>
  <div class="public-layout">
    <!-- 安全模式提示橫幅 -->
    <div :class="['mode-banner', securityModeStore.mode]">
      <div class="banner-content">
        <span class="mode-icon">{{ securityModeStore.isVulnerable ? '🔓' : '🔒' }}</span>
        <span class="mode-text">{{ securityModeStore.modeLabel }}</span>
        <span class="mode-desc">{{ securityModeStore.modeDescription }}</span>
        <el-switch
          v-model="isSecureMode"
          active-text="安全"
          inactive-text="漏洞"
          inline-prompt
          :active-action-icon="Lock"
          :inactive-action-icon="Unlock"
          @change="handleModeChange"
        />
      </div>
    </div>

    <!-- 頂部導航 -->
    <el-header class="header">
      <div class="header-content">
        <div class="logo" @click="router.push('/')">
          <el-icon :size="24"><ShoppingBag /></el-icon>
          <span>OWASP Demo 商城</span>
        </div>

        <el-menu
          mode="horizontal"
          :ellipsis="false"
          :default-active="route.path"
          router
          class="nav-menu"
        >
          <el-menu-item index="/">首頁</el-menu-item>
          <el-menu-item index="/products">商品列表</el-menu-item>
          <el-menu-item index="/flash-sale">限時搶購</el-menu-item>
          <el-menu-item index="/cart">購物車</el-menu-item>
          <el-menu-item index="/checkout">結帳</el-menu-item>
        </el-menu>

        <div class="header-right">
          <template v-if="!authStore.isLoggedIn">
            <el-button @click="router.push('/auth/login')">登入</el-button>
            <el-button type="primary" @click="router.push('/auth/register')">註冊</el-button>
          </template>
          <template v-else>
            <el-dropdown>
              <el-button>
                {{ authStore.user?.username }}
                <el-icon class="el-icon--right"><ArrowDown /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item @click="router.push('/profile')">
                    會員中心
                  </el-dropdown-item>
                  <el-dropdown-item v-if="authStore.isAdmin" @click="router.push('/admin')">
                    管理後台
                  </el-dropdown-item>
                  <el-dropdown-item divided @click="handleLogout">登出</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </template>
        </div>
      </div>
    </el-header>

    <!-- 主內容區 -->
    <el-main class="main-content">
      <router-view />
    </el-main>

    <!-- 底部 -->
    <el-footer class="footer">
      <p>OWASP 弱點教學網站 © 2024 - 僅供教學使用</p>
      <p class="footer-api">
        當前 API: {{ securityModeStore.isVulnerable ? 'http://localhost:8081' : 'http://localhost:8082' }}
      </p>
    </el-footer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ShoppingBag, ArrowDown, Lock, Unlock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useSecurityModeStore, useAuthStore } from '@/stores'
import api from '@/api'

const route = useRoute()
const router = useRouter()
const securityModeStore = useSecurityModeStore()
const authStore = useAuthStore()

// 安全模式切換
const isSecureMode = computed({
  get: () => securityModeStore.mode === 'secure',
  set: (val) => securityModeStore.setMode(val ? 'secure' : 'vulnerable')
})

// 處理模式切換
const handleModeChange = async (val) => {
  const modeName = val ? '安全模式' : '漏洞模式'
  ElMessage.success(`已切換至 ${modeName}`)
  
  // 重新取得系統狀態
  try {
    const response = await api.getStatus()
    securityModeStore.setApiStatus(response.data)
  } catch (error) {
    console.error('無法取得系統狀態', error)
  }
}

// 登出
const handleLogout = () => {
  authStore.logout()
  ElMessage.success('已登出')
  router.push('/')
}

// 取得系統狀態
const fetchSystemStatus = async () => {
  try {
    const response = await api.getStatus()
    securityModeStore.setApiStatus(response.data)
  } catch (error) {
    console.error('無法取得系統狀態', error)
  }
}

onMounted(() => {
  fetchSystemStatus()
})

// 監聽模式變化，重新取得狀態
watch(() => securityModeStore.mode, () => {
  fetchSystemStatus()
})
</script>

<style lang="scss" scoped>
.public-layout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.mode-banner {
  padding: 8px 0;
  text-align: center;
  font-size: 14px;
  
  &.vulnerable {
    background: linear-gradient(90deg, #ff4d4f 0%, #ff7875 100%);
    color: white;
  }
  
  &.secure {
    background: linear-gradient(90deg, #52c41a 0%, #73d13d 100%);
    color: white;
  }
  
  .banner-content {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
    
    .mode-icon {
      font-size: 18px;
    }
    
    .mode-text {
      font-weight: 600;
    }
    
    .mode-desc {
      opacity: 0.9;
      margin-right: 16px;
    }
  }
}

.header {
  background: #fff;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 0;
  height: 60px;
  position: sticky;
  top: 0;
  z-index: 100;

  .header-content {
    max-width: 1200px;
    margin: 0 auto;
    height: 100%;
    display: flex;
    align-items: center;
    padding: 0 20px;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 18px;
    font-weight: 600;
    color: #409eff;
    cursor: pointer;
  }

  .nav-menu {
    flex: 1;
    margin-left: 40px;
    border: none;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }
}

.main-content {
  flex: 1;
  padding: 24px;
  max-width: 1200px;
  margin: 0 auto;
  width: 100%;
}

.footer {
  background: #303133;
  color: #909399;
  text-align: center;
  padding: 20px;
  
  .footer-api {
    font-size: 12px;
    margin-top: 8px;
    opacity: 0.7;
  }
}
</style>

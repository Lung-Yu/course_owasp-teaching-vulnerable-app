<template>
  <div class="admin-layout">
    <el-container>
      <!-- 側邊欄 -->
      <el-aside :width="isCollapse ? '64px' : '220px'" class="aside">
        <div class="logo">
          <el-icon :size="24"><Setting /></el-icon>
          <span v-show="!isCollapse">管理後台</span>
        </div>

        <el-menu
          :default-active="route.path"
          :collapse="isCollapse"
          router
          class="admin-menu"
        >
          <el-menu-item index="/admin">
            <el-icon><DataAnalysis /></el-icon>
            <span>儀表板</span>
          </el-menu-item>
          <el-menu-item index="/admin/products">
            <el-icon><Goods /></el-icon>
            <span>商品管理</span>
          </el-menu-item>
          <el-menu-item index="/admin/orders">
            <el-icon><List /></el-icon>
            <span>訂單管理</span>
          </el-menu-item>
          <el-menu-item index="/admin/users">
            <el-icon><User /></el-icon>
            <span>會員管理</span>
          </el-menu-item>
          <el-menu-item index="/admin/system-tools">
            <el-icon><Monitor /></el-icon>
            <span>系統工具</span>
          </el-menu-item>
          <el-divider />
          <el-menu-item index="/">
            <el-icon><Back /></el-icon>
            <span>返回前台</span>
          </el-menu-item>
        </el-menu>
      </el-aside>

      <el-container>
        <!-- 頂部 -->
        <el-header class="header">
          <div class="header-left">
            <el-button :icon="isCollapse ? Expand : Fold" @click="isCollapse = !isCollapse" text />
            <el-breadcrumb separator="/">
              <el-breadcrumb-item :to="{ path: '/admin' }">管理後台</el-breadcrumb-item>
              <el-breadcrumb-item v-if="route.meta.title !== '管理後台'">
                {{ route.meta.title }}
              </el-breadcrumb-item>
            </el-breadcrumb>
          </div>

          <div class="header-right">
            <el-tag
              :type="systemStatus.securityMode === 'vulnerable' ? 'danger' : 'success'"
              effect="dark"
            >
              {{ systemStatus.securityMode === 'vulnerable' ? '漏洞模式' : '安全模式' }}
            </el-tag>
            <el-dropdown>
              <span class="user-info">
                <el-avatar :size="32" icon="UserFilled" />
                <span>管理員</span>
              </span>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item @click="handleLogout">登出</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </el-header>

        <!-- 主內容 -->
        <el-main class="main-content">
          <router-view />
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  Setting,
  DataAnalysis,
  Goods,
  List,
  User,
  Back,
  Fold,
  Expand,
  Monitor,
} from '@element-plus/icons-vue'
import api from '@/api'

const route = useRoute()
const router = useRouter()

const isCollapse = ref(false)
const systemStatus = ref({ securityMode: 'vulnerable' })

const fetchSystemStatus = async () => {
  try {
    const response = await api.getStatus()
    systemStatus.value = response.data
  } catch (error) {
    console.error('無法取得系統狀態', error)
  }
}

const handleLogout = () => {
  router.push('/auth/login')
}

onMounted(() => {
  fetchSystemStatus()
})
</script>

<style lang="scss" scoped>
.admin-layout {
  min-height: 100vh;

  .el-container {
    min-height: 100vh;
  }
}

.aside {
  background: #304156;
  transition: width 0.3s;

  .logo {
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    color: #fff;
    font-size: 18px;
    font-weight: 600;
    border-bottom: 1px solid #3d4a5a;
  }

  .admin-menu {
    border: none;
    background: transparent;

    :deep(.el-menu-item) {
      color: #bfcbd9;

      &:hover {
        background: #263445;
      }

      &.is-active {
        color: #409eff;
        background: #263445;
      }
    }
  }
}

.header {
  background: #fff;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;

  .header-left {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 16px;

    .user-info {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
    }
  }
}

.main-content {
  background: #f0f2f5;
  padding: 24px;
}
</style>

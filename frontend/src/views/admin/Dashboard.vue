<template>
  <div class="dashboard">
    <div class="page-header">
      <h1>管理後台</h1>
      <p class="subtitle">歡迎回來，管理員</p>
    </div>

    <!-- 統計卡片 -->
    <el-row :gutter="24" class="stats-row">
      <el-col :span="6" v-for="stat in stats" :key="stat.title">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" :style="{ background: stat.color }">
            <el-icon :size="24"><component :is="stat.icon" /></el-icon>
          </div>
          <div class="stat-info">
            <span class="stat-value">{{ stat.value }}</span>
            <span class="stat-title">{{ stat.title }}</span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 安全模式資訊 -->
    <el-card class="mode-card">
      <template #header>
        <span>當前安全模式</span>
      </template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="模式">
          <el-tag :type="systemStatus.securityMode === 'vulnerable' ? 'danger' : 'success'" size="large">
            {{ systemStatus.securityMode === 'vulnerable' ? '🔓 漏洞模式' : '🔒 安全模式' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="說明">
          {{ systemStatus.description || '無' }}
        </el-descriptions-item>
        <el-descriptions-item label="SQL Injection">
          <el-tag :type="vulnerabilities.sqlInjection ? 'danger' : 'success'" size="small">
            {{ vulnerabilities.sqlInjection ? '啟用' : '已修復' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="XSS">
          <el-tag :type="vulnerabilities.xss ? 'danger' : 'success'" size="small">
            {{ vulnerabilities.xss ? '啟用' : '已修復' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="身份驗證漏洞">
          <el-tag :type="vulnerabilities.brokenAuth ? 'danger' : 'success'" size="small">
            {{ vulnerabilities.brokenAuth ? '啟用' : '已修復' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="存取控制漏洞">
          <el-tag :type="vulnerabilities.brokenAccessControl ? 'danger' : 'success'" size="small">
            {{ vulnerabilities.brokenAccessControl ? '啟用' : '已修復' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- 快速操作 -->
    <el-card class="quick-actions">
      <template #header>
        <span>快速操作</span>
      </template>
      <el-row :gutter="16">
        <el-col :span="6">
          <el-button type="primary" size="large" @click="router.push('/admin/products')" class="action-btn">
            <el-icon><Goods /></el-icon>
            管理商品
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button type="success" size="large" @click="router.push('/admin/orders')" class="action-btn">
            <el-icon><List /></el-icon>
            管理訂單
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button type="warning" size="large" @click="router.push('/admin/users')" class="action-btn">
            <el-icon><User /></el-icon>
            管理會員
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button size="large" @click="router.push('/')" class="action-btn">
            <el-icon><View /></el-icon>
            查看前台
          </el-button>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ShoppingCart, User, Goods, List, View } from '@element-plus/icons-vue'
import api from '@/api'

const router = useRouter()

const systemStatus = ref({
  securityMode: 'vulnerable',
  description: '',
})

const vulnerabilities = reactive({
  sqlInjection: true,
  xss: true,
  brokenAuth: true,
  brokenAccessControl: true,
})

const stats = ref([
  { title: '商品數量', value: '-', icon: Goods, color: '#409eff' },
  { title: '訂單數量', value: '-', icon: List, color: '#67c23a' },
  { title: '會員數量', value: '-', icon: User, color: '#e6a23c' },
  { title: '今日銷售', value: '-', icon: ShoppingCart, color: '#f56c6c' },
])

const fetchStats = async () => {
  try {
    const response = await api.adminGetStats()
    const data = response.data
    
    stats.value = [
      { title: '商品數量', value: data.productCount ?? data.products ?? '-', icon: Goods, color: '#409eff' },
      { title: '訂單數量', value: data.orderCount ?? data.orders ?? '-', icon: List, color: '#67c23a' },
      { title: '會員數量', value: data.userCount ?? data.users ?? '-', icon: User, color: '#e6a23c' },
      { title: '今日銷售', value: data.todaySales ? `NT$ ${data.todaySales.toLocaleString()}` : '-', icon: ShoppingCart, color: '#f56c6c' },
    ]
  } catch (error) {
    console.error('取得統計資料失敗', error)
  }
}

onMounted(async () => {
  try {
    const response = await api.getStatus()
    systemStatus.value = response.data
    if (response.data.vulnerabilities) {
      Object.assign(vulnerabilities, response.data.vulnerabilities)
    }
  } catch (error) {
    console.error('無法取得系統狀態', error)
  }
  
  // 取得統計資料
  fetchStats()
})
</script>

<style lang="scss" scoped>
.dashboard {
  .page-header {
    margin-bottom: 24px;

    h1 {
      font-size: 28px;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #909399;
    }
  }
}

.stats-row {
  margin-bottom: 24px;
}

.stat-card {
  display: flex;
  align-items: center;
  padding: 8px;

  :deep(.el-card__body) {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 16px;
  }

  .stat-icon {
    width: 56px;
    height: 56px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    margin-right: 16px;
  }

  .stat-info {
    display: flex;
    flex-direction: column;

    .stat-value {
      font-size: 24px;
      font-weight: 600;
      color: #303133;
    }

    .stat-title {
      font-size: 14px;
      color: #909399;
    }
  }
}

.mode-card {
  margin-bottom: 24px;
}

.quick-actions {
  .action-btn {
    width: 100%;
    height: 80px;
    flex-direction: column;
    gap: 8px;

    .el-icon {
      font-size: 24px;
    }
  }
}
</style>

<template>
  <div class="home-page">
    <!-- Banner -->
    <section class="banner">
      <div class="banner-content">
        <h1>OWASP 弱點教學商城</h1>
        <p>透過實際案例學習 Web 應用程式安全</p>
        <el-tag :type="securityMode === 'vulnerable' ? 'danger' : 'success'" size="large" effect="dark">
          目前模式：{{ securityMode === 'vulnerable' ? '🔓 漏洞展示' : '🔒 安全模式' }}
        </el-tag>
      </div>
    </section>

    <!-- 功能介紹 -->
    <section class="features">
      <h2>學習目標</h2>
      <el-row :gutter="24">
        <el-col :span="8" v-for="feature in features" :key="feature.title">
          <el-card shadow="hover" class="feature-card">
            <div class="feature-icon">
              <el-icon :size="48" :color="feature.color">
                <component :is="feature.icon" />
              </el-icon>
            </div>
            <h3>{{ feature.title }}</h3>
            <p>{{ feature.description }}</p>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <!-- 快速連結 -->
    <section class="quick-links">
      <h2>開始探索</h2>
      <el-row :gutter="24">
        <el-col :span="12">
          <el-card shadow="hover" class="link-card" @click="router.push('/products')">
            <el-icon :size="32"><Goods /></el-icon>
            <h3>瀏覽商品</h3>
            <p>查看商品列表，體驗搜尋功能</p>
          </el-card>
        </el-col>
        <el-col :span="12">
          <el-card shadow="hover" class="link-card" @click="router.push('/auth/login')">
            <el-icon :size="32"><User /></el-icon>
            <h3>登入系統</h3>
            <p>登入會員帳號，存取更多功能</p>
          </el-card>
        </el-col>
      </el-row>
    </section>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Warning, Lock, Document, Goods, User } from '@element-plus/icons-vue'
import api from '@/api'

const router = useRouter()

const securityMode = ref('vulnerable')

const features = [
  {
    icon: Warning,
    title: 'SQL Injection',
    description: '學習 SQL 注入攻擊的原理與防禦方法',
    color: '#f56c6c',
  },
  {
    icon: Lock,
    title: '身份驗證漏洞',
    description: '了解常見的認證缺陷與安全實作',
    color: '#e6a23c',
  },
  {
    icon: Document,
    title: 'XSS 攻擊',
    description: '認識跨站腳本攻擊與輸出編碼',
    color: '#409eff',
  },
]

onMounted(async () => {
  try {
    const response = await api.getStatus()
    securityMode.value = response.data.securityMode
  } catch (error) {
    console.error('無法取得系統狀態', error)
  }
})
</script>

<style lang="scss" scoped>
.home-page {
  h2 {
    text-align: center;
    margin-bottom: 32px;
    font-size: 28px;
    color: #303133;
  }
}

.banner {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 12px;
  padding: 60px 40px;
  text-align: center;
  color: #fff;
  margin-bottom: 48px;

  h1 {
    font-size: 36px;
    margin-bottom: 16px;
  }

  p {
    font-size: 18px;
    margin-bottom: 24px;
    opacity: 0.9;
  }
}

.features {
  margin-bottom: 48px;

  .feature-card {
    text-align: center;
    padding: 24px;
    cursor: default;

    .feature-icon {
      margin-bottom: 16px;
    }

    h3 {
      font-size: 18px;
      margin-bottom: 8px;
      color: #303133;
    }

    p {
      color: #909399;
      font-size: 14px;
    }
  }
}

.quick-links {
  .link-card {
    text-align: center;
    padding: 32px;
    cursor: pointer;
    transition: transform 0.3s;

    &:hover {
      transform: translateY(-4px);
    }

    h3 {
      margin: 16px 0 8px;
      font-size: 20px;
      color: #303133;
    }

    p {
      color: #909399;
    }
  }
}
</style>

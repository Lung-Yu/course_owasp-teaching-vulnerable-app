<template>
  <div class="login-page">
    <el-card class="login-card">
      <template #header>
        <div class="card-header">
          <h2>會員登入</h2>
          <el-tag :type="securityModeStore.isVulnerable ? 'danger' : 'success'" size="small">
            {{ securityModeStore.modeLabel }}
          </el-tag>
        </div>
      </template>

      <!-- 漏洞模式提示 -->
      <el-alert
        v-if="securityModeStore.isVulnerable"
        type="warning"
        show-icon
        :closable="false"
        class="vuln-alert"
      >
        <template #title>
          ⚠️ A07 認證失敗漏洞示範
        </template>
        <template #default>
          <p>此頁面存在多種認證漏洞：</p>
          <ul style="margin: 8px 0; padding-left: 20px;">
            <li>SQL Injection：輸入 <code>' OR '1'='1</code> 作為帳號</li>
            <li>暴力破解：無登入次數限制</li>
            <li>帳號枚舉：錯誤訊息洩露帳號是否存在</li>
          </ul>
        </template>
      </el-alert>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        @submit.prevent="handleLogin"
      >
        <el-form-item label="帳號" prop="username">
          <el-input
            v-model="form.username"
            placeholder="請輸入帳號"
            :prefix-icon="User"
            size="large"
          />
        </el-form-item>

        <el-form-item label="密碼" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="請輸入密碼"
            :prefix-icon="Lock"
            size="large"
            show-password
          />
        </el-form-item>

        <el-form-item>
          <div class="form-row">
            <el-checkbox v-model="form.rememberMe">記住我</el-checkbox>
            <el-link type="primary" @click="router.push('/auth/forgot-password')">忘記密碼？</el-link>
          </div>
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            native-type="submit"
            class="login-btn"
          >
            登入
          </el-button>
        </el-form-item>
      </el-form>

      <!-- 登入嘗試計數 (A07 無速率限制) -->
      <div v-if="loginAttempts > 0" class="attempt-counter">
        <el-tag type="info" size="small">
          登入嘗試次數: {{ loginAttempts }} 
          <span v-if="securityModeStore.isVulnerable" style="color: #f56c6c;">（無限制！）</span>
        </el-tag>
      </div>

      <div class="login-footer">
        <span>還沒有帳號？</span>
        <el-link type="primary" @click="router.push('/auth/register')">立即註冊</el-link>
      </div>

      <el-divider>測試帳號</el-divider>
      <div class="test-accounts">
        <el-button size="small" @click="fillTestAccount('user')">一般使用者</el-button>
        <el-button size="small" @click="fillTestAccount('admin')">管理員</el-button>
      </div>

      <!-- 暴力破解演示 -->
      <el-divider v-if="securityModeStore.isVulnerable">🔓 暴力破解演示 (A07)</el-divider>
      <div v-if="securityModeStore.isVulnerable" class="brute-force-demo">
        <el-input v-model="bruteForceTarget" placeholder="目標帳號" size="small" style="margin-bottom: 8px;" />
        <el-button 
          type="danger" 
          size="small" 
          @click="startBruteForce" 
          :loading="bruteForcing"
          :disabled="!bruteForceTarget"
          style="width: 100%;"
        >
          🔓 開始暴力破解
        </el-button>
        
        <div v-if="bruteForceResult" class="brute-result">
          <div class="result-header">破解結果 (嘗試 {{ bruteForceAttempts }} 次)</div>
          <div v-if="bruteForceResult.success" class="result-success">
            ✅ 密碼破解成功: <code>{{ bruteForceResult.password }}</code>
          </div>
          <div v-else class="result-fail">
            ❌ 破解失敗，常見密碼皆不符
          </div>
          <div class="result-log">
            <div v-for="(log, idx) in bruteForceLog.slice(-5)" :key="idx" class="log-item">
              {{ log }}
            </div>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { User, Lock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useSecurityModeStore, useAuthStore } from '@/stores'
import api from '@/api'

const router = useRouter()
const securityModeStore = useSecurityModeStore()
const authStore = useAuthStore()

const formRef = ref()
const loading = ref(false)
const loginAttempts = ref(0)

// 暴力破解演示
const bruteForceTarget = ref('admin')
const bruteForcing = ref(false)
const bruteForceResult = ref(null)
const bruteForceAttempts = ref(0)
const bruteForceLog = ref([])

const form = reactive({
  username: '',
  password: '',
  rememberMe: false,
})

const rules = {
  username: [{ required: true, message: '請輸入帳號', trigger: 'blur' }],
  password: [{ required: true, message: '請輸入密碼', trigger: 'blur' }],
}

const handleLogin = async () => {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  loginAttempts.value++
  
  try {
    const response = await api.login({
      username: form.username,
      password: form.password
    })
    
    // 儲存認證資訊
    authStore.setAuth(response.data)
    
    ElMessage.success('登入成功')
    
    if (response.data.role === 'ADMIN') {
      router.push('/admin')
    } else {
      router.push('/')
    }
  } catch (error) {
    const errorMsg = error.response?.data?.error || '登入失敗，請檢查帳號密碼'
    ElMessage.error(errorMsg)
  } finally {
    loading.value = false
  }
}

const fillTestAccount = (type) => {
  if (type === 'admin') {
    form.username = 'admin'
    form.password = 'admin123'
  } else {
    form.username = 'user'
    form.password = 'user123'
  }
}

// 常見弱密碼清單
const commonPasswords = [
  '123456', 'password', '123456789', '12345678', '12345',
  '1234567', '1234567890', 'qwerty', 'abc123', 'password1',
  'admin', 'admin123', 'root', 'toor', 'pass',
  'test', 'guest', 'master', 'changeme', 'welcome',
  'user123', 'password123', 'letmein', 'iloveyou', '000000'
]

const startBruteForce = async () => {
  if (!bruteForceTarget.value) return
  
  bruteForcing.value = true
  bruteForceResult.value = null
  bruteForceAttempts.value = 0
  bruteForceLog.value = []
  
  for (const password of commonPasswords) {
    bruteForceAttempts.value++
    bruteForceLog.value.push(`嘗試 ${bruteForceAttempts.value}: ${bruteForceTarget.value}:${password}`)
    
    try {
      const response = await api.login({
        username: bruteForceTarget.value,
        password: password
      })
      
      // 成功登入
      bruteForceResult.value = {
        success: true,
        password: password,
        user: response.data
      }
      bruteForceLog.value.push(`✅ 成功! 密碼是: ${password}`)
      ElMessage.success(`暴力破解成功！密碼是: ${password}`)
      bruteForcing.value = false
      return
    } catch (error) {
      // 繼續嘗試下一個密碼
      await new Promise(r => setTimeout(r, 100)) // 模擬延遲
    }
  }
  
  // 所有密碼都試過了
  bruteForceResult.value = { success: false }
  bruteForceLog.value.push('❌ 所有常見密碼都已嘗試，破解失敗')
  bruteForcing.value = false
}
</script>

<style lang="scss" scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.login-card {
  width: 100%;
  max-width: 480px;

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;

    h2 {
      margin: 0;
      font-size: 24px;
    }
  }

  .vuln-alert {
    margin-bottom: 20px;
    
    code {
      background: #f5f5f5;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: monospace;
    }
  }

  .form-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
  }

  .login-btn {
    width: 100%;
  }

  .attempt-counter {
    text-align: center;
    margin-bottom: 16px;
  }

  .login-footer {
    text-align: center;
    color: #909399;

    .el-link {
      margin-left: 4px;
    }
  }

  .test-accounts {
    display: flex;
    justify-content: center;
    gap: 12px;
  }

  .brute-force-demo {
    .brute-result {
      margin-top: 12px;
      background: #1e1e1e;
      border-radius: 8px;
      padding: 12px;
      color: #fff;

      .result-header {
        font-weight: bold;
        margin-bottom: 8px;
        color: #909399;
      }

      .result-success {
        color: #67c23a;
        font-size: 14px;
        
        code {
          background: #2d3a2d;
          padding: 2px 8px;
          border-radius: 4px;
        }
      }

      .result-fail {
        color: #f56c6c;
      }

      .result-log {
        margin-top: 8px;
        max-height: 100px;
        overflow-y: auto;
        font-size: 11px;
        font-family: monospace;
        color: #909399;

        .log-item {
          padding: 2px 0;
        }
      }
    }
  }
}
</style>

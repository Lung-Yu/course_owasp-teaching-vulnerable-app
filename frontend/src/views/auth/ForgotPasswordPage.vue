<template>
  <div class="forgot-page">
    <el-card class="forgot-card">
      <template #header>
        <div class="card-header">
          <h2>忘記密碼</h2>
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
          ⚠️ A07 可預測密碼重設 Token
        </template>
        <template #default>
          <p>此頁面的密碼重設 Token 使用可預測的演算法：</p>
          <code>MD5(username + "fixed-secret-2024")</code>
          <p style="margin-top: 8px;">攻擊者可以直接計算出任意使用者的重設連結！</p>
        </template>
      </el-alert>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        @submit.prevent="handleSubmit"
      >
        <el-form-item label="使用者帳號" prop="username">
          <el-input
            v-model="form.username"
            placeholder="請輸入您的帳號"
            :prefix-icon="User"
            size="large"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            native-type="submit"
            class="submit-btn"
          >
            取得重設連結
          </el-button>
        </el-form-item>
      </el-form>

      <!-- 重設結果 -->
      <div v-if="resetResult" class="reset-result">
        <el-alert type="success" show-icon :closable="false">
          <template #title>密碼重設連結已產生</template>
          <template #default>
            <div class="result-content">
              <p><strong>重設 Token:</strong></p>
              <code class="token-display">{{ resetResult.token }}</code>
              
              <p style="margin-top: 12px;"><strong>重設連結:</strong></p>
              <el-input 
                :value="resetResult.resetUrl" 
                readonly 
                size="small"
              >
                <template #append>
                  <el-button @click="copyLink">複製</el-button>
                </template>
              </el-input>
            </div>
          </template>
        </el-alert>
      </div>

      <!-- Token 預測攻擊演示 -->
      <el-divider v-if="securityModeStore.isVulnerable">🔓 Token 預測攻擊 (A07)</el-divider>
      <div v-if="securityModeStore.isVulnerable" class="token-attack-demo">
        <p class="demo-desc">
          由於 Token 使用 <code>MD5(username + "fixed-secret-2024")</code> 產生，
          攻擊者只需知道目標帳號即可計算出重設連結。
        </p>
        
        <el-input v-model="attackTarget" placeholder="目標帳號 (如: admin)" size="small" style="margin-bottom: 8px;">
          <template #prepend>目標</template>
        </el-input>
        
        <el-button 
          type="danger" 
          size="small" 
          @click="predictToken" 
          :loading="predicting"
          :disabled="!attackTarget"
          style="width: 100%;"
        >
          🔮 預測重設 Token
        </el-button>
        
        <div v-if="predictedToken" class="predict-result">
          <div class="result-header">預測結果</div>
          <div class="result-row">
            <span>目標帳號:</span>
            <code>{{ attackTarget }}</code>
          </div>
          <div class="result-row">
            <span>預測 Token:</span>
            <code>{{ predictedToken }}</code>
          </div>
          <div class="result-row">
            <span>重設連結:</span>
            <code class="url">{{ predictedUrl }}</code>
          </div>
          <el-button 
            type="warning" 
            size="small" 
            @click="testPredictedToken" 
            style="width: 100%; margin-top: 8px;"
          >
            🎯 使用預測的 Token 重設密碼
          </el-button>
        </div>
      </div>

      <div class="page-footer">
        <el-link type="primary" @click="router.push('/auth/login')">
          ← 返回登入
        </el-link>
      </div>
    </el-card>

    <!-- 重設密碼對話框 -->
    <el-dialog v-model="showResetDialog" title="重設密碼" width="400px">
      <el-form :model="resetForm" label-position="top">
        <el-form-item label="新密碼">
          <el-input v-model="resetForm.newPassword" type="password" placeholder="輸入新密碼" show-password />
        </el-form-item>
        <el-form-item label="確認密碼">
          <el-input v-model="resetForm.confirmPassword" type="password" placeholder="再次輸入新密碼" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showResetDialog = false">取消</el-button>
        <el-button type="primary" @click="executeReset" :loading="resetting">重設密碼</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useRouter } from 'vue-router'
import { User } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useSecurityModeStore } from '@/stores'
import api from '@/api'

const router = useRouter()
const securityModeStore = useSecurityModeStore()

const formRef = ref()
const loading = ref(false)
const resetResult = ref(null)

// Token 預測攻擊
const attackTarget = ref('admin')
const predicting = ref(false)
const predictedToken = ref('')
const predictedUrl = computed(() => 
  predictedToken.value ? `${window.location.origin}/auth/reset-password?token=${predictedToken.value}` : ''
)

// 重設密碼對話框
const showResetDialog = ref(false)
const resetting = ref(false)
const resetForm = reactive({
  newPassword: 'hacked123',
  confirmPassword: 'hacked123'
})

const form = reactive({
  username: '',
})

const rules = {
  username: [{ required: true, message: '請輸入帳號', trigger: 'blur' }],
}

const handleSubmit = async () => {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  try {
    const response = await api.forgotPassword({
      username: form.username
    })
    
    resetResult.value = {
      token: response.data.token,
      resetUrl: `${window.location.origin}/auth/reset-password?token=${response.data.token}`
    }
    
    ElMessage.success('密碼重設連結已產生')
  } catch (error) {
    ElMessage.error(error.response?.data?.error || '產生重設連結失敗')
  } finally {
    loading.value = false
  }
}

const copyLink = () => {
  if (resetResult.value) {
    navigator.clipboard.writeText(resetResult.value.resetUrl)
    ElMessage.success('已複製到剪貼簿')
  }
}

// 模擬 MD5 (簡化版，實際應該呼叫 API)
const simpleMD5 = (str) => {
  // 這只是展示用，實際計算會呼叫後端
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash).toString(16).padStart(32, '0').substring(0, 32)
}

const predictToken = async () => {
  if (!attackTarget.value) return
  
  predicting.value = true
  
  try {
    // 呼叫後端 crypto/hash 來計算真正的 MD5
    const response = await api.cryptoHash({
      data: attackTarget.value + 'fixed-secret-2024',
      algorithm: 'MD5'
    })
    
    predictedToken.value = response.data.hash
    ElMessage.warning(`Token 已預測！使用 MD5("${attackTarget.value}" + "fixed-secret-2024")`)
  } catch (error) {
    // 如果 API 失敗，使用模擬值
    predictedToken.value = simpleMD5(attackTarget.value + 'fixed-secret-2024')
    ElMessage.warning('Token 已預測（模擬計算）')
  } finally {
    predicting.value = false
  }
}

const testPredictedToken = () => {
  showResetDialog.value = true
}

const executeReset = async () => {
  if (resetForm.newPassword !== resetForm.confirmPassword) {
    ElMessage.error('兩次輸入的密碼不一致')
    return
  }
  
  resetting.value = true
  
  try {
    await api.resetPassword({
      token: predictedToken.value,
      newPassword: resetForm.newPassword
    })
    
    ElMessage.success(`密碼重設成功！${attackTarget.value} 的新密碼是: ${resetForm.newPassword}`)
    showResetDialog.value = false
  } catch (error) {
    ElMessage.error(error.response?.data?.error || '密碼重設失敗')
  } finally {
    resetting.value = false
  }
}
</script>

<style lang="scss" scoped>
.forgot-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.forgot-card {
  width: 100%;
  max-width: 500px;

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
      background: #fff3e0;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: monospace;
      display: inline-block;
      margin: 4px 0;
    }
  }

  .submit-btn {
    width: 100%;
  }

  .reset-result {
    margin-top: 16px;

    .result-content {
      code {
        display: block;
        background: #f5f5f5;
        padding: 8px;
        border-radius: 4px;
        font-family: monospace;
        word-break: break-all;
      }

      .token-display {
        font-size: 12px;
        color: #f56c6c;
      }
    }
  }

  .token-attack-demo {
    .demo-desc {
      font-size: 13px;
      color: #909399;
      margin-bottom: 12px;

      code {
        background: #f5f5f5;
        padding: 2px 4px;
        border-radius: 2px;
        font-size: 11px;
      }
    }

    .predict-result {
      margin-top: 12px;
      background: #1e1e1e;
      border-radius: 8px;
      padding: 12px;
      color: #fff;

      .result-header {
        font-weight: bold;
        margin-bottom: 8px;
        color: #67c23a;
      }

      .result-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 4px 0;
        font-size: 12px;

        span {
          color: #909399;
        }

        code {
          color: #f56c6c;
          font-family: monospace;
          
          &.url {
            font-size: 10px;
            word-break: break-all;
          }
        }
      }
    }
  }

  .page-footer {
    text-align: center;
    margin-top: 24px;
  }
}
</style>

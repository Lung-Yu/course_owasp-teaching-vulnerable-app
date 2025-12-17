<template>
  <div class="profile-page">
    <el-row :gutter="24">
      <el-col :span="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <h2>會員資料</h2>
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
              ⚠️ A02 敏感資料外洩
            </template>
            <template #default>
              <p>此頁面存在敏感資料外洩漏洞：</p>
              <ul style="margin: 8px 0; padding-left: 20px;">
                <li>密碼雜湊值使用弱演算法 (MD5)</li>
                <li>信用卡資訊使用弱加密 (DES)</li>
                <li>API 回傳過多敏感欄位</li>
              </ul>
            </template>
          </el-alert>

          <el-form :model="userInfo" label-width="100px" v-loading="loading">
            <el-form-item label="使用者 ID">
              <el-input :value="userInfo.id" disabled />
            </el-form-item>
            <el-form-item label="帳號">
              <el-input :value="userInfo.username" disabled />
            </el-form-item>
            <el-form-item label="Email">
              <el-input v-model="userInfo.email" />
            </el-form-item>
            <el-form-item label="姓名">
              <el-input v-model="userInfo.fullName" />
            </el-form-item>
            <el-form-item label="電話">
              <el-input v-model="userInfo.phone" />
            </el-form-item>
            <el-form-item label="地址">
              <el-input v-model="userInfo.address" type="textarea" :rows="2" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveProfile">儲存變更</el-button>
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 訂單紀錄 -->
        <el-card style="margin-top: 20px;">
          <template #header>最近訂單</template>
          <el-empty v-if="orders.length === 0" description="尚無訂單" />
          <el-table v-else :data="orders" stripe>
            <el-table-column prop="orderNumber" label="訂單編號" width="150" />
            <el-table-column prop="totalAmount" label="金額" width="100">
              <template #default="{ row }">
                NT$ {{ row.totalAmount }}
              </template>
            </el-table-column>
            <el-table-column prop="status" label="狀態" width="100">
              <template #default="{ row }">
                <el-tag :type="getStatusType(row.status)" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="createdAt" label="日期" />
          </el-table>
        </el-card>
      </el-col>

      <el-col :span="8">
        <!-- 敏感資料區塊 (漏洞演示) -->
        <el-card v-if="securityModeStore.isVulnerable" class="sensitive-card">
          <template #header>
            <div class="card-header">
              <span>🔓 敏感資料 (A02)</span>
              <el-tag type="danger" size="small">外洩風險</el-tag>
            </div>
          </template>

          <el-button 
            type="danger" 
            @click="fetchSensitiveData" 
            :loading="fetchingSensitive"
            style="width: 100%; margin-bottom: 16px;"
          >
            取得敏感資料 (API 漏洞)
          </el-button>

          <div v-if="sensitiveData" class="sensitive-display">
            <div class="data-section">
              <div class="section-title">🔑 密碼雜湊 (MD5)</div>
              <code class="hash-value">{{ sensitiveData.passwordHash }}</code>
              <p class="warning-text">⚠️ MD5 可被彩虹表破解</p>
            </div>

            <div class="data-section">
              <div class="section-title">💳 信用卡資訊 (DES 加密)</div>
              <div class="card-info">
                <div>加密卡號: <code>{{ sensitiveData.encryptedCard }}</code></div>
                <div>加密金鑰: <code class="key-exposed">{{ sensitiveData.encryptionKey }}</code></div>
              </div>
              <el-button 
                type="warning" 
                size="small" 
                @click="decryptCard"
                :loading="decrypting"
                style="width: 100%; margin-top: 8px;"
              >
                🔓 解密信用卡號
              </el-button>
              <div v-if="decryptedCard" class="decrypted-result">
                解密結果: <code>{{ decryptedCard }}</code>
              </div>
            </div>

            <div class="data-section">
              <div class="section-title">📧 其他敏感資料</div>
              <div class="other-data">
                <div>帳戶餘額: <code>NT$ {{ sensitiveData.balance }}</code></div>
                <div>會員等級: <code>{{ sensitiveData.memberLevel }}</code></div>
                <div>註冊 IP: <code>{{ sensitiveData.registrationIp }}</code></div>
              </div>
            </div>
          </div>
        </el-card>

        <!-- 變更密碼 -->
        <el-card :style="{ marginTop: securityModeStore.isVulnerable ? '20px' : '0' }">
          <template #header>變更密碼</template>
          
          <el-alert
            v-if="securityModeStore.isVulnerable"
            type="warning"
            size="small"
            show-icon
            :closable="false"
            style="margin-bottom: 16px;"
          >
            ⚠️ 漏洞：不需要輸入舊密碼即可變更
          </el-alert>

          <el-form :model="passwordForm" label-position="top">
            <el-form-item v-if="!securityModeStore.isVulnerable" label="目前密碼">
              <el-input v-model="passwordForm.oldPassword" type="password" show-password />
            </el-form-item>
            <el-form-item label="新密碼">
              <el-input v-model="passwordForm.newPassword" type="password" show-password />
            </el-form-item>
            <el-form-item label="確認新密碼">
              <el-input v-model="passwordForm.confirmPassword" type="password" show-password />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="changePassword" :loading="changingPassword" style="width: 100%;">
                變更密碼
              </el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useSecurityModeStore, useAuthStore } from '@/stores'
import api from '@/api'

const securityModeStore = useSecurityModeStore()
const authStore = useAuthStore()

const loading = ref(false)
const orders = ref([])

const userInfo = reactive({
  id: authStore.user?.id || 1,
  username: authStore.user?.username || 'user',
  email: 'user@example.com',
  fullName: '測試用戶',
  phone: '0912345678',
  address: '台北市信義區信義路五段7號',
})

// 敏感資料
const fetchingSensitive = ref(false)
const sensitiveData = ref(null)
const decrypting = ref(false)
const decryptedCard = ref('')

// 密碼變更
const changingPassword = ref(false)
const passwordForm = reactive({
  oldPassword: '',
  newPassword: '',
  confirmPassword: ''
})

const fetchUserInfo = async () => {
  loading.value = true
  try {
    const userId = authStore.user?.id || 1
    const response = await api.getUser(userId)
    Object.assign(userInfo, response.data)
  } catch (error) {
    // 使用預設資料
  } finally {
    loading.value = false
  }
}

const fetchOrders = async () => {
  try {
    const response = await api.getOrders()
    orders.value = response.data?.slice(0, 5) || []
  } catch (error) {
    // 使用空陣列
  }
}

const saveProfile = async () => {
  try {
    await api.updateUser(userInfo.id, userInfo)
    ElMessage.success('資料已更新')
  } catch (error) {
    ElMessage.error('更新失敗')
  }
}

const getStatusType = (status) => {
  const types = {
    'PENDING': 'warning',
    'CONFIRMED': 'primary',
    'SHIPPED': 'info',
    'DELIVERED': 'success',
    'CANCELLED': 'danger'
  }
  return types[status] || 'info'
}

// 取得敏感資料 (漏洞演示)
const fetchSensitiveData = async () => {
  fetchingSensitive.value = true
  
  try {
    // 呼叫有漏洞的 API 端點
    const response = await api.getUser(userInfo.id)
    
    // 模擬敏感資料外洩
    sensitiveData.value = {
      passwordHash: response.data?.passwordHash || '5f4dcc3b5aa765d61d8327deb882cf99', // "password" 的 MD5
      encryptedCard: response.data?.encryptedCard || 'A7F2C9E831B4D6F0', // DES 加密的卡號
      encryptionKey: 'MySecret', // 硬編碼金鑰外洩!
      balance: response.data?.balance || 50000,
      memberLevel: response.data?.role || 'VIP',
      registrationIp: '192.168.1.100'
    }
    
    ElMessage.warning('敏感資料已外洩！這是 A02 漏洞演示')
  } catch (error) {
    // 模擬資料
    sensitiveData.value = {
      passwordHash: '5f4dcc3b5aa765d61d8327deb882cf99',
      encryptedCard: 'A7F2C9E831B4D6F0',
      encryptionKey: 'MySecret',
      balance: 50000,
      memberLevel: 'VIP',
      registrationIp: '192.168.1.100'
    }
    ElMessage.warning('敏感資料已外洩！（模擬資料）')
  } finally {
    fetchingSensitive.value = false
  }
}

// 解密信用卡 (漏洞演示)
const decryptCard = async () => {
  if (!sensitiveData.value) return
  
  decrypting.value = true
  
  try {
    const response = await api.cryptoDecrypt({
      data: sensitiveData.value.encryptedCard,
      key: sensitiveData.value.encryptionKey,
      algorithm: 'DES'
    })
    
    decryptedCard.value = response.data?.decrypted || '4111-1111-1111-1111'
    ElMessage.error('信用卡號已被解密！使用外洩的金鑰')
  } catch (error) {
    // 模擬解密結果
    decryptedCard.value = '4111-1111-1111-1111'
    ElMessage.error('信用卡號已被解密！（模擬）')
  } finally {
    decrypting.value = false
  }
}

// 變更密碼
const changePassword = async () => {
  if (passwordForm.newPassword !== passwordForm.confirmPassword) {
    ElMessage.error('兩次輸入的密碼不一致')
    return
  }
  
  changingPassword.value = true
  
  try {
    await api.changePassword({
      userId: userInfo.id,
      oldPassword: passwordForm.oldPassword,
      newPassword: passwordForm.newPassword
    })
    
    ElMessage.success('密碼已變更')
    passwordForm.oldPassword = ''
    passwordForm.newPassword = ''
    passwordForm.confirmPassword = ''
  } catch (error) {
    ElMessage.error(error.response?.data?.error || '密碼變更失敗')
  } finally {
    changingPassword.value = false
  }
}

onMounted(() => {
  fetchUserInfo()
  fetchOrders()
})
</script>

<style lang="scss" scoped>
.profile-page {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;

    h2 {
      margin: 0;
      font-size: 20px;
    }
  }

  .vuln-alert {
    margin-bottom: 20px;
  }

  .sensitive-card {
    border-color: #f56c6c;

    .sensitive-display {
      .data-section {
        background: #1e1e1e;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 12px;

        .section-title {
          color: #909399;
          font-size: 12px;
          margin-bottom: 8px;
        }

        code {
          display: block;
          background: #2d2d2d;
          color: #f56c6c;
          padding: 6px 8px;
          border-radius: 4px;
          font-family: monospace;
          font-size: 11px;
          word-break: break-all;
        }

        .hash-value {
          color: #e6a23c;
        }

        .key-exposed {
          color: #f56c6c;
          font-weight: bold;
        }

        .warning-text {
          color: #e6a23c;
          font-size: 11px;
          margin-top: 4px;
        }

        .card-info {
          font-size: 12px;
          color: #909399;
          
          code {
            display: inline;
            padding: 2px 4px;
          }
        }

        .decrypted-result {
          margin-top: 8px;
          padding: 8px;
          background: #2d1a1a;
          border-radius: 4px;
          color: #f56c6c;
          font-size: 12px;

          code {
            display: inline;
            color: #67c23a;
            background: none;
            padding: 0;
          }
        }

        .other-data {
          font-size: 12px;
          color: #c0c4cc;

          code {
            display: inline;
            padding: 2px 4px;
            color: #67c23a;
          }
        }
      }
    }
  }
}
</style>

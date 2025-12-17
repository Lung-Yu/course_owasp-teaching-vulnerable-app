<template>
  <div class="checkout-page">
    <div class="page-header">
      <h1>結帳</h1>
      <p class="subtitle">確認訂單並完成付款（A02 密碼學失敗演示）</p>
    </div>

    <el-alert
      v-if="securityModeStore.isVulnerable"
      type="warning"
      show-icon
      :closable="false"
      class="vuln-alert"
    >
      <template #title>
        ⚠️ A02 密碼學失敗漏洞
      </template>
      <template #default>
        <p>此頁面存在多種密碼學漏洞：</p>
        <ul style="margin: 8px 0; padding-left: 20px;">
          <li>信用卡使用 DES 弱加密 + 硬編碼金鑰</li>
          <li>訂單驗證碼使用 MD5 弱雜湊</li>
          <li>加密金鑰直接寫在前端程式碼</li>
        </ul>
      </template>
    </el-alert>

    <el-row :gutter="24">
      <el-col :span="16">
        <!-- 收件資訊 -->
        <el-card class="section-card">
          <template #header>📦 收件資訊</template>
          <el-form :model="shippingForm" label-width="80px">
            <el-form-item label="收件人">
              <el-input v-model="shippingForm.name" placeholder="請輸入收件人姓名" />
            </el-form-item>
            <el-form-item label="電話">
              <el-input v-model="shippingForm.phone" placeholder="請輸入聯絡電話" />
            </el-form-item>
            <el-form-item label="地址">
              <el-input v-model="shippingForm.address" placeholder="請輸入收件地址" type="textarea" :rows="2" />
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 付款資訊 -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>💳 付款資訊</span>
              <el-tag v-if="securityModeStore.isVulnerable" type="danger" size="small">
                DES 弱加密
              </el-tag>
            </div>
          </template>
          
          <el-form :model="paymentForm" label-width="80px">
            <el-form-item label="卡號">
              <el-input 
                v-model="paymentForm.cardNumber" 
                placeholder="1234 5678 9012 3456"
                maxlength="19"
              />
            </el-form-item>
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item label="有效期">
                  <el-input v-model="paymentForm.expiry" placeholder="MM/YY" maxlength="5" />
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item label="CVV">
                  <el-input v-model="paymentForm.cvv" placeholder="123" type="password" maxlength="4" />
                </el-form-item>
              </el-col>
            </el-row>
            <el-form-item label="持卡人">
              <el-input v-model="paymentForm.cardHolder" placeholder="與信用卡上姓名相同" />
            </el-form-item>
          </el-form>

          <!-- 加密演示 (漏洞模式) -->
          <div v-if="securityModeStore.isVulnerable" class="crypto-demo">
            <el-divider>🔓 加密過程演示</el-divider>
            
            <div class="demo-section">
              <div class="demo-row">
                <span class="label">加密演算法:</span>
                <code class="danger">DES (已過時、不安全)</code>
              </div>
              <div class="demo-row">
                <span class="label">加密金鑰:</span>
                <code class="danger">{{ HARDCODED_KEY }}</code>
                <el-tag type="danger" size="small" style="margin-left: 8px;">硬編碼!</el-tag>
              </div>
            </div>

            <el-button 
              type="warning" 
              @click="showEncryptionProcess" 
              :loading="encrypting"
              style="width: 100%; margin-top: 12px;"
            >
              🔐 模擬加密信用卡資料
            </el-button>

            <div v-if="encryptionResult" class="encryption-result">
              <div class="result-row">
                <span>原始卡號:</span>
                <code>{{ paymentForm.cardNumber || '4111111111111111' }}</code>
              </div>
              <div class="result-row">
                <span>加密後:</span>
                <code class="encrypted">{{ encryptionResult.encrypted }}</code>
              </div>
              <div class="result-row warning">
                <span>⚠️ 金鑰外洩:</span>
                <code class="danger">{{ encryptionResult.key }}</code>
              </div>
              
              <el-button 
                type="danger" 
                size="small"
                @click="decryptCardNumber"
                :loading="decrypting"
                style="width: 100%; margin-top: 8px;"
              >
                🔓 使用外洩金鑰解密
              </el-button>
              
              <div v-if="decryptedCardNumber" class="decrypted-result">
                ✅ 解密成功: <code>{{ decryptedCardNumber }}</code>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="8">
        <!-- 訂單摘要 -->
        <el-card class="summary-card">
          <template #header>訂單摘要</template>
          
          <div class="order-items">
            <div v-for="item in cartItems" :key="item.id" class="order-item">
              <span class="item-name">{{ item.name }}</span>
              <span class="item-qty">x{{ item.quantity }}</span>
              <span class="item-price">NT$ {{ item.price * item.quantity }}</span>
            </div>
          </div>

          <el-divider />

          <div class="summary-row">
            <span>商品小計</span>
            <span>NT$ {{ subtotal }}</span>
          </div>
          <div class="summary-row">
            <span>運費</span>
            <span>NT$ {{ shipping }}</span>
          </div>
          <el-divider />
          <div class="summary-row total">
            <span>總計</span>
            <span>NT$ {{ total }}</span>
          </div>

          <el-button 
            type="primary" 
            size="large" 
            @click="placeOrder" 
            :loading="placing"
            style="width: 100%; margin-top: 16px;"
          >
            確認付款
          </el-button>
        </el-card>

        <!-- 訂單驗證碼 (漏洞演示) -->
        <el-card v-if="orderPlaced" class="verification-card">
          <template #header>
            <div class="card-header">
              <span>📋 訂單驗證</span>
              <el-tag v-if="securityModeStore.isVulnerable" type="danger" size="small">MD5</el-tag>
            </div>
          </template>
          
          <div class="verification-info">
            <div class="info-row">
              <span>訂單編號:</span>
              <code>{{ orderResult.orderNumber }}</code>
            </div>
            <div class="info-row">
              <span>驗證碼:</span>
              <code class="hash">{{ orderResult.verificationCode }}</code>
            </div>
          </div>

          <div v-if="securityModeStore.isVulnerable" class="hash-warning">
            <p>⚠️ 驗證碼使用 MD5 產生:</p>
            <code>MD5(orderId + amount + "secret123")</code>
            <p style="margin-top: 8px; color: #f56c6c;">
              攻擊者可計算任意訂單的驗證碼！
            </p>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { useSecurityModeStore } from '@/stores'
import api from '@/api'

const securityModeStore = useSecurityModeStore()

// 硬編碼金鑰 (漏洞演示)
const HARDCODED_KEY = 'MySecret'

const cartItems = ref([
  { id: 1, name: 'MacBook Pro 14吋', price: 59900, quantity: 1 },
  { id: 2, name: 'iPhone 15 Pro', price: 36900, quantity: 1 },
])

const shippingForm = reactive({
  name: '測試用戶',
  phone: '0912345678',
  address: '台北市信義區信義路五段7號'
})

const paymentForm = reactive({
  cardNumber: '4111111111111111',
  expiry: '12/25',
  cvv: '123',
  cardHolder: 'TEST USER'
})

const encrypting = ref(false)
const encryptionResult = ref(null)
const decrypting = ref(false)
const decryptedCardNumber = ref('')
const placing = ref(false)
const orderPlaced = ref(false)
const orderResult = ref(null)

const subtotal = computed(() => 
  cartItems.value.reduce((sum, item) => sum + item.price * item.quantity, 0)
)
const shipping = ref(100)
const total = computed(() => subtotal.value + shipping.value)

// 模擬加密過程
const showEncryptionProcess = async () => {
  encrypting.value = true
  encryptionResult.value = null
  decryptedCardNumber.value = ''

  try {
    const response = await api.cryptoEncrypt({
      data: paymentForm.cardNumber || '4111111111111111',
      key: HARDCODED_KEY,
      algorithm: 'DES'
    })

    encryptionResult.value = {
      encrypted: response.data?.encrypted || 'A7F2C9E831B4D6F0123456789ABCDEF',
      key: response.data?.key || HARDCODED_KEY
    }
    
    ElMessage.warning('加密完成，但金鑰已外洩在回應中！')
  } catch (error) {
    // 模擬結果
    encryptionResult.value = {
      encrypted: 'A7F2C9E831B4D6F0123456789ABCDEF',
      key: HARDCODED_KEY
    }
    ElMessage.warning('加密完成（模擬），但金鑰已外洩！')
  } finally {
    encrypting.value = false
  }
}

// 解密
const decryptCardNumber = async () => {
  if (!encryptionResult.value) return
  
  decrypting.value = true

  try {
    const response = await api.cryptoDecrypt({
      data: encryptionResult.value.encrypted,
      key: encryptionResult.value.key,
      algorithm: 'DES'
    })

    decryptedCardNumber.value = response.data?.decrypted || paymentForm.cardNumber
    ElMessage.error('信用卡號被解密！這就是使用弱加密+外洩金鑰的風險')
  } catch (error) {
    decryptedCardNumber.value = paymentForm.cardNumber || '4111111111111111'
    ElMessage.error('信用卡號被解密！（模擬）')
  } finally {
    decrypting.value = false
  }
}

// 下單
const placeOrder = async () => {
  placing.value = true

  try {
    const response = await api.createOrder({
      items: cartItems.value,
      shipping: shippingForm,
      total: total.value
    })

    orderPlaced.value = true
    orderResult.value = {
      orderNumber: response.data?.orderNumber || `ORD-${Date.now()}`,
      verificationCode: response.data?.verificationCode || 'e99a18c428cb38d5f260853678922e03'
    }
    
    ElMessage.success('訂單已建立！')
  } catch (error) {
    // 模擬成功
    orderPlaced.value = true
    orderResult.value = {
      orderNumber: `ORD-${Date.now()}`,
      verificationCode: 'e99a18c428cb38d5f260853678922e03'
    }
    ElMessage.success('訂單已建立！（模擬）')
  } finally {
    placing.value = false
  }
}
</script>

<style lang="scss" scoped>
.checkout-page {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;

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

  .vuln-alert {
    margin-bottom: 24px;
  }

  .section-card {
    margin-bottom: 20px;

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
  }

  .crypto-demo {
    background: #fafafa;
    border-radius: 8px;
    padding: 16px;
    margin-top: 16px;

    .demo-section {
      background: #1e1e1e;
      border-radius: 8px;
      padding: 12px;

      .demo-row {
        display: flex;
        align-items: center;
        padding: 4px 0;
        font-size: 13px;

        .label {
          color: #909399;
          width: 100px;
        }

        code {
          background: #2d2d2d;
          color: #67c23a;
          padding: 2px 6px;
          border-radius: 4px;
          font-family: monospace;

          &.danger {
            color: #f56c6c;
          }
        }
      }
    }

    .encryption-result {
      background: #1e1e1e;
      border-radius: 8px;
      padding: 12px;
      margin-top: 12px;

      .result-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 4px 0;
        font-size: 12px;
        color: #909399;

        code {
          color: #67c23a;
          font-family: monospace;

          &.encrypted {
            color: #409eff;
            font-size: 11px;
          }

          &.danger {
            color: #f56c6c;
            font-weight: bold;
          }
        }

        &.warning {
          color: #e6a23c;
        }
      }

      .decrypted-result {
        margin-top: 8px;
        padding: 8px;
        background: #2d1a1a;
        border-radius: 4px;
        color: #67c23a;
        font-size: 12px;
        text-align: center;

        code {
          color: #f56c6c;
        }
      }
    }
  }

  .summary-card {
    .order-items {
      .order-item {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        font-size: 14px;

        .item-name {
          flex: 1;
        }

        .item-qty {
          width: 40px;
          text-align: center;
          color: #909399;
        }

        .item-price {
          width: 100px;
          text-align: right;
          font-weight: 500;
        }
      }
    }

    .summary-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      color: #606266;

      &.total {
        font-size: 18px;
        font-weight: 600;
        color: #303133;
      }
    }
  }

  .verification-card {
    margin-top: 20px;

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .verification-info {
      .info-row {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        font-size: 14px;

        code {
          background: #f5f5f5;
          padding: 2px 8px;
          border-radius: 4px;
          font-family: monospace;

          &.hash {
            font-size: 11px;
            color: #e6a23c;
          }
        }
      }
    }

    .hash-warning {
      margin-top: 16px;
      padding: 12px;
      background: #1e1e1e;
      border-radius: 8px;
      font-size: 12px;
      color: #909399;

      code {
        display: block;
        background: #2d2d2d;
        color: #f56c6c;
        padding: 8px;
        border-radius: 4px;
        margin-top: 4px;
        font-family: monospace;
      }
    }
  }
}
</style>

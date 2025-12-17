<template>
  <div class="cart-page">
    <div class="page-header">
      <h1>購物車</h1>
      <p class="subtitle">查看您的購物車商品（A08 資料完整性演示）</p>
    </div>

    <el-alert type="warning" show-icon :closable="false" class="warning-alert">
      <template #title>
        ⚠️ 安全警告：此頁面在漏洞模式下存在購物車竄改漏洞
      </template>
      <div class="alert-content">
        <p>漏洞版本允許客戶端修改商品價格和數量，未驗證資料完整性</p>
      </div>
    </el-alert>

    <el-row :gutter="24">
      <el-col :span="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>購物車商品</span>
              <el-button type="danger" text @click="clearCart" :disabled="cartItems.length === 0">
                清空購物車
              </el-button>
            </div>
          </template>

          <el-empty v-if="cartItems.length === 0" description="購物車是空的" />

          <el-table v-else :data="cartItems" stripe>
            <el-table-column prop="name" label="商品名稱" min-width="200" />
            <el-table-column label="單價" width="150">
              <template #default="{ row }">
                <div class="price-cell">
                  <span v-if="!row.editing">NT$ {{ row.price }}</span>
                  <el-input-number 
                    v-else 
                    v-model="row.price" 
                    :min="0" 
                    size="small"
                    style="width: 100px"
                  />
                  <el-button 
                    type="warning" 
                    size="small" 
                    text 
                    @click="row.editing = !row.editing"
                    class="edit-btn"
                  >
                    {{ row.editing ? '確定' : '修改' }}
                  </el-button>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="數量" width="150">
              <template #default="{ row }">
                <el-input-number v-model="row.quantity" :min="1" :max="99" size="small" />
              </template>
            </el-table-column>
            <el-table-column label="小計" width="120">
              <template #default="{ row }">
                <span class="subtotal">NT$ {{ row.price * row.quantity }}</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="80">
              <template #default="{ row, $index }">
                <el-button type="danger" size="small" text @click="removeItem($index)">
                  移除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <el-col :span="8">
        <!-- 訂單摘要 -->
        <el-card class="summary-card">
          <template #header>訂單摘要</template>
          
          <div class="summary-row">
            <span>商品數量</span>
            <span>{{ totalItems }} 件</span>
          </div>
          <div class="summary-row">
            <span>商品小計</span>
            <span>NT$ {{ subtotal }}</span>
          </div>
          <div class="summary-row" v-if="discount > 0">
            <span>折扣</span>
            <span class="discount">-NT$ {{ discount }}</span>
          </div>
          <el-divider />
          <div class="summary-row total">
            <span>總計</span>
            <span>NT$ {{ total }}</span>
          </div>

          <!-- 優惠券 (A04) -->
          <div class="coupon-section">
            <el-input 
              v-model="couponCode" 
              placeholder="輸入優惠券代碼"
              class="coupon-input"
            >
              <template #append>
                <el-button @click="applyCoupon" :loading="applyingCoupon">
                  套用
                </el-button>
              </template>
            </el-input>
            <div v-if="couponMessage" :class="['coupon-message', couponSuccess ? 'success' : 'error']">
              {{ couponMessage }}
            </div>
          </div>

          <el-button type="primary" size="large" class="checkout-btn" @click="checkout" :loading="checkingOut">
            結帳
          </el-button>
        </el-card>

        <!-- 購物車竄改演示 -->
        <el-card class="demo-card">
          <template #header>
            <div class="card-header">
              <span>🔓 購物車竄改演示</span>
              <el-tag type="danger" size="small">A08</el-tag>
            </div>
          </template>
          <el-button type="warning" @click="tamperCart" :loading="tampering" style="width: 100%">
            竄改購物車資料
          </el-button>
          <p class="demo-desc">
            在漏洞模式下，此操作會繞過伺服器驗證，直接修改購物車金額
          </p>
          <div v-if="tamperResult" class="result-box">
            <pre>{{ JSON.stringify(tamperResult, null, 2) }}</pre>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

const router = useRouter()

const cartItems = ref([
  { id: 1, name: 'MacBook Pro 14吋', price: 59900, quantity: 1, editing: false },
  { id: 2, name: 'iPhone 15 Pro', price: 36900, quantity: 2, editing: false },
])

const couponCode = ref('')
const couponMessage = ref('')
const couponSuccess = ref(false)
const applyingCoupon = ref(false)
const discount = ref(0)
const checkingOut = ref(false)
const tampering = ref(false)
const tamperResult = ref(null)

const totalItems = computed(() => 
  cartItems.value.reduce((sum, item) => sum + item.quantity, 0)
)

const subtotal = computed(() => 
  cartItems.value.reduce((sum, item) => sum + item.price * item.quantity, 0)
)

const total = computed(() => Math.max(0, subtotal.value - discount.value))

const removeItem = (index) => {
  cartItems.value.splice(index, 1)
}

const clearCart = () => {
  ElMessageBox.confirm('確定要清空購物車嗎？', '警告', {
    confirmButtonText: '確定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(() => {
    cartItems.value = []
    discount.value = 0
    couponCode.value = ''
    couponMessage.value = ''
  }).catch(() => {})
}

const applyCoupon = async () => {
  if (!couponCode.value) {
    couponMessage.value = '請輸入優惠券代碼'
    couponSuccess.value = false
    return
  }

  applyingCoupon.value = true
  couponMessage.value = ''

  try {
    const response = await api.applyCoupon({
      code: couponCode.value,
      cartTotal: subtotal.value
    })
    
    if (response.data.valid) {
      discount.value = response.data.discount || Math.floor(subtotal.value * 0.1)
      couponMessage.value = `優惠券套用成功！折扣 NT$ ${discount.value}`
      couponSuccess.value = true
    } else {
      couponMessage.value = response.data.message || '優惠券無效'
      couponSuccess.value = false
    }
  } catch (error) {
    // 模擬成功（漏洞模式）
    discount.value = Math.floor(subtotal.value * 0.2)
    couponMessage.value = `優惠券套用成功！折扣 NT$ ${discount.value}`
    couponSuccess.value = true
  } finally {
    applyingCoupon.value = false
  }
}

const tamperCart = async () => {
  tampering.value = true
  tamperResult.value = null

  try {
    // 發送竄改的購物車資料到 /integrity/cart/save
    const tamperedItems = cartItems.value.map(item => ({
      productId: item.id,
      name: item.name,
      price: 1, // 將價格改為 1 元
      quantity: item.quantity
    }))
    
    const response = await api.integritySaveCart({
      items: tamperedItems,
      total: tamperedItems.length, // 總金額改為商品數量
      originalTotal: subtotal.value,
      tampered: true
    })
    
    tamperResult.value = {
      success: true,
      message: '購物車資料已竄改成功！',
      originalTotal: subtotal.value,
      tamperedTotal: tamperedItems.length,
      savedCartId: response.data.cartId,
      serverResponse: response.data
    }
    ElMessage.success('購物車資料已竄改並保存到伺服器！')
  } catch (error) {
    tamperResult.value = { 
      error: error.response?.data?.error || error.response?.data?.detail || error.message,
      message: '竄改失敗'
    }
    ElMessage.warning('竄改失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    tampering.value = false
  }
}

const checkout = async () => {
  if (cartItems.value.length === 0) {
    ElMessage.warning('購物車是空的')
    return
  }

  checkingOut.value = true
  
  try {
    await api.checkout({
      items: cartItems.value,
      total: total.value,
      couponCode: couponCode.value || undefined
    })
    
    ElMessage.success('訂單已成功建立！')
    cartItems.value = []
    discount.value = 0
  } catch (error) {
    ElMessage.error('結帳失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    checkingOut.value = false
  }
}

onMounted(async () => {
  // 嘗試從 API 取得購物車（如果有的話）
  try {
    const response = await api.getCart()
    if (response.data && Array.isArray(response.data.items)) {
      cartItems.value = response.data.items.map(item => ({
        ...item,
        editing: false
      }))
    }
  } catch (error) {
    // 使用預設的模擬資料
    console.log('使用模擬購物車資料')
  }
})
</script>

<style lang="scss" scoped>
.cart-page {
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

  .warning-alert {
    margin-bottom: 24px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .price-cell {
    display: flex;
    align-items: center;
    gap: 8px;
    
    .edit-btn {
      padding: 0;
    }
  }

  .subtotal {
    font-weight: 600;
    color: #f56c6c;
  }

  .summary-card {
    margin-bottom: 16px;

    .summary-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 12px;
      color: #606266;

      &.total {
        font-size: 18px;
        font-weight: 600;
        color: #303133;
      }

      .discount {
        color: #67c23a;
      }
    }

    .coupon-section {
      margin: 16px 0;

      .coupon-input {
        margin-bottom: 8px;
      }

      .coupon-message {
        font-size: 12px;
        
        &.success {
          color: #67c23a;
        }
        
        &.error {
          color: #f56c6c;
        }
      }
    }

    .checkout-btn {
      width: 100%;
      margin-top: 16px;
    }
  }

  .demo-card {
    .demo-desc {
      font-size: 12px;
      color: #909399;
      margin-top: 12px;
    }

    .result-box {
      margin-top: 12px;
      background: #1e1e1e;
      border-radius: 4px;
      padding: 12px;

      pre {
        color: #67c23a;
        font-size: 12px;
        margin: 0;
        white-space: pre-wrap;
      }
    }
  }
}
</style>

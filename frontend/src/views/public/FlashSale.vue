<template>
  <div class="flash-sale">
    <div class="page-header">
      <h1>🔥 限時搶購</h1>
      <p class="subtitle">超值商品限量搶購（A04 競態條件演示）</p>
    </div>

    <el-alert type="warning" show-icon :closable="false" class="warning-alert">
      <template #title>
        ⚠️ 安全警告：此頁面在漏洞模式下存在競態條件漏洞
      </template>
      <div class="alert-content">
        <p>漏洞版本沒有正確處理並發請求，可能導致超賣。嘗試同時發送多個購買請求。</p>
      </div>
    </el-alert>

    <!-- 商品列表 -->
    <el-row :gutter="24">
      <el-col :span="8" v-for="product in flashSaleProducts" :key="product.id">
        <el-card class="product-card" :class="{ 'sold-out': product.remaining <= 0 }">
          <div class="product-image">
            <img :src="product.imageUrl || '/placeholder.jpg'" :alt="product.name" />
            <div v-if="product.remaining <= 0" class="sold-out-overlay">
              <span>已售罄</span>
            </div>
          </div>
          
          <div class="product-info">
            <h3>{{ product.name }}</h3>
            <div class="price-row">
              <span class="original-price">NT$ {{ product.originalPrice }}</span>
              <span class="flash-price">NT$ {{ product.flashPrice }}</span>
            </div>
            <div class="stock-info">
              <span>剩餘數量：</span>
              <el-tag :type="product.remaining > 0 ? 'success' : 'danger'">
                {{ product.remaining }} / {{ product.totalStock }}
              </el-tag>
            </div>
            <el-progress 
              :percentage="(product.remaining / product.totalStock) * 100"
              :status="product.remaining > 0 ? '' : 'exception'"
              :stroke-width="10"
              class="stock-progress"
            />
          </div>

          <div class="product-actions">
            <el-button 
              type="danger" 
              size="large" 
              :disabled="product.remaining <= 0 || product.buying"
              :loading="product.buying"
              @click="buyProduct(product)"
              class="buy-btn"
            >
              {{ product.remaining > 0 ? '立即搶購' : '已售罄' }}
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 競態條件演示 -->
    <el-card class="demo-card">
      <template #header>
        <div class="card-header">
          <span>🔓 競態條件攻擊演示</span>
          <el-tag type="danger" size="small">A04</el-tag>
        </div>
      </template>
      
      <el-row :gutter="16">
        <el-col :span="8">
          <el-form-item label="目標商品">
            <el-select v-model="raceTarget" placeholder="選擇商品" style="width: 100%">
              <el-option 
                v-for="p in flashSaleProducts" 
                :key="p.id" 
                :label="p.name" 
                :value="p.id" 
              />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="並發請求數">
            <el-input-number v-model="concurrentRequests" :min="2" :max="20" style="width: 100%" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="操作">
            <el-button type="danger" @click="launchRaceAttack" :loading="attacking" style="width: 100%">
              發起競態攻擊
            </el-button>
          </el-form-item>
        </el-col>
      </el-row>

      <el-alert type="info" :closable="false" class="demo-info">
        此演示會同時發送多個購買請求。在漏洞模式下，可能會成功購買超過庫存數量的商品。
      </el-alert>

      <div v-if="attackResults.length > 0" class="attack-results">
        <h4>攻擊結果</h4>
        <div class="result-summary">
          <el-tag type="success">成功: {{ successCount }}</el-tag>
          <el-tag type="danger">失敗: {{ failCount }}</el-tag>
        </div>
        <div class="result-box">
          <div v-for="(result, index) in attackResults" :key="index" class="result-item">
            <span :class="['status', result.success ? 'success' : 'error']">
              {{ result.success ? '✓' : '✗' }}
            </span>
            <span class="message">{{ result.message }}</span>
          </div>
        </div>
      </div>
    </el-card>

    <!-- 重置按鈕 -->
    <div class="reset-section">
      <el-button @click="refreshProducts" :loading="loading">
        重新整理庫存
      </el-button>
      <el-button type="warning" @click="resetFlashSale" :loading="resetting">
        重置限時搶購
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const resetting = ref(false)
const attacking = ref(false)

const flashSaleProducts = ref([])

const raceTarget = ref(null)
const concurrentRequests = ref(5)
const attackResults = ref([])

const successCount = computed(() => attackResults.value.filter(r => r.success).length)
const failCount = computed(() => attackResults.value.filter(r => !r.success).length)

const refreshProducts = async () => {
  loading.value = true
  try {
    const response = await api.getFlashSales()
    if (response.data && response.data.flashSales) {
      flashSaleProducts.value = response.data.flashSales.map(p => ({
        id: p.id,
        name: p.productName,
        originalPrice: p.originalPrice,
        flashPrice: p.flashPrice,
        totalStock: p.stockLimit,
        remaining: p.remaining,
        buying: false
      }))
      // 設定預設目標
      if (flashSaleProducts.value.length > 0 && !raceTarget.value) {
        raceTarget.value = flashSaleProducts.value[0].id
      }
    }
  } catch (error) {
    console.log('使用模擬資料', error)
    // 使用模擬資料
    flashSaleProducts.value = [
      { id: 1, name: '限量版 MacBook Pro', originalPrice: 59900, flashPrice: 29900, totalStock: 5, remaining: 5, buying: false },
      { id: 2, name: '限量版 AirPods Pro', originalPrice: 7490, flashPrice: 4990, totalStock: 10, remaining: 10, buying: false },
    ]
    raceTarget.value = 1
  } finally {
    loading.value = false
  }
}

const buyProduct = async (product) => {
  product.buying = true
  
  try {
    const response = await api.buyFlashSale(product.id, 1)
    
    if (response.data.message) {
      // 更新剩餘庫存
      if (response.data.stockRemaining !== undefined) {
        product.remaining = response.data.stockRemaining
      } else {
        product.remaining = Math.max(0, product.remaining - 1)
      }
      ElMessage.success(`成功搶購「${product.name}」！`)
    } else if (response.data.error) {
      ElMessage.warning(response.data.error)
    }
  } catch (error) {
    const errorMsg = error.response?.data?.error || '購買失敗'
    ElMessage.warning(errorMsg)
  } finally {
    product.buying = false
  }
}

const launchRaceAttack = async () => {
  if (!raceTarget.value) {
    ElMessage.warning('請選擇目標商品')
    return
  }

  attacking.value = true
  attackResults.value = []

  const targetProduct = flashSaleProducts.value.find(p => p.id === raceTarget.value)
  
  // 同時發送多個請求（競態條件攻擊）
  const promises = []
  for (let i = 0; i < concurrentRequests.value; i++) {
    promises.push(
      api.buyFlashSale(raceTarget.value, 1)
        .then(response => ({
          success: !response.data.error,
          message: response.data.message || response.data.error || `請求 ${i + 1}: 購買成功`,
          remaining: response.data.stockRemaining
        }))
        .catch(error => ({
          success: false,
          message: `請求 ${i + 1}: ${error.response?.data?.error || '購買失敗'}`
        }))
    )
  }

  try {
    const results = await Promise.all(promises)
    attackResults.value = results
    
    // 更新庫存顯示
    if (targetProduct) {
      const lastSuccessResult = results.filter(r => r.success && r.remaining !== undefined).pop()
      if (lastSuccessResult) {
        targetProduct.remaining = lastSuccessResult.remaining
      } else {
        targetProduct.remaining = Math.max(0, targetProduct.remaining - successCount.value)
      }
    }

    if (successCount.value > 0) {
      ElMessage.success(`攻擊完成：成功 ${successCount.value} 次，失敗 ${failCount.value} 次`)
    }
  } finally {
    attacking.value = false
  }
}

const resetFlashSale = async () => {
  resetting.value = true
  
  try {
    await api.resetFlashSale()
    // 重新從 API 載入資料
    await refreshProducts()
    attackResults.value = []
    ElMessage.success('限時搶購已重置')
  } catch (error) {
    // 即使 API 失敗也嘗試重新載入
    await refreshProducts()
    attackResults.value = []
    ElMessage.warning('重置可能未完全成功，已重新載入資料')
  } finally {
    resetting.value = false
  }
}

onMounted(() => {
  refreshProducts()
})
</script>

<style lang="scss" scoped>
.flash-sale {
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

  .product-card {
    margin-bottom: 24px;
    transition: all 0.3s;

    &:hover {
      transform: translateY(-4px);
      box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
    }

    &.sold-out {
      opacity: 0.7;
    }

    .product-image {
      height: 180px;
      background: #f5f7fa;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 16px;
      position: relative;
      overflow: hidden;

      img {
        max-width: 100%;
        max-height: 100%;
        object-fit: contain;
      }

      .sold-out-overlay {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;

        span {
          color: #fff;
          font-size: 24px;
          font-weight: 600;
        }
      }
    }

    .product-info {
      h3 {
        font-size: 18px;
        margin-bottom: 12px;
      }

      .price-row {
        margin-bottom: 12px;

        .original-price {
          text-decoration: line-through;
          color: #909399;
          margin-right: 12px;
        }

        .flash-price {
          font-size: 24px;
          font-weight: 600;
          color: #f56c6c;
        }
      }

      .stock-info {
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .stock-progress {
        margin-bottom: 16px;
      }
    }

    .buy-btn {
      width: 100%;
    }
  }

  .demo-card {
    margin-top: 24px;

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .demo-info {
      margin: 16px 0;
    }

    .attack-results {
      margin-top: 16px;

      h4 {
        margin-bottom: 12px;
      }

      .result-summary {
        display: flex;
        gap: 12px;
        margin-bottom: 12px;
      }

      .result-box {
        background: #1e1e1e;
        border-radius: 8px;
        padding: 16px;
        max-height: 200px;
        overflow-y: auto;

        .result-item {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 4px;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 13px;

          .status {
            &.success { color: #67c23a; }
            &.error { color: #f56c6c; }
          }

          .message {
            color: #fff;
          }
        }
      }
    }
  }

  .reset-section {
    margin-top: 24px;
    text-align: center;
  }
}
</style>

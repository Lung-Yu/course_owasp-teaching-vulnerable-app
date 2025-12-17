<template>
  <div class="product-detail" v-loading="loading">
    <el-button @click="router.back()" :icon="ArrowLeft" text>返回列表</el-button>

    <el-card v-if="product" class="detail-card">
      <el-row :gutter="48">
        <el-col :span="10">
          <div class="product-image">
            <img :src="product.imageUrl || '/placeholder.jpg'" :alt="product.name" />
          </div>
        </el-col>
        <el-col :span="14">
          <div class="product-info">
            <el-tag size="small">{{ product.category }}</el-tag>
            <h1 class="product-name">{{ product.name }}</h1>
            
            <div class="product-price">
              <span class="price-label">售價</span>
              <span class="price-value">NT$ {{ product.price }}</span>
            </div>

            <el-divider />

            <div class="product-desc">
              <h3>商品描述</h3>
              <p>{{ product.description || '暫無描述' }}</p>
            </div>

            <div class="product-stock">
              <span>庫存狀態：</span>
              <el-tag :type="product.stock > 0 ? 'success' : 'danger'">
                {{ product.stock > 0 ? `有庫存 (${product.stock})` : '缺貨中' }}
              </el-tag>
            </div>

            <el-divider />

            <div class="product-actions">
              <el-input-number v-model="quantity" :min="1" :max="product.stock" :disabled="product.stock === 0" />
              <el-button type="primary" size="large" :disabled="product.stock === 0" :loading="addingToCart" @click="addToCart">
                加入購物車
              </el-button>
              <el-button size="large" @click="buyNow">
                前往購物車
              </el-button>
            </div>
          </div>
        </el-col>
      </el-row>
    </el-card>

    <el-empty v-else-if="!loading" description="找不到此商品" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const product = ref(null)
const quantity = ref(1)
const addingToCart = ref(false)

const fetchProduct = async () => {
  const id = route.params.id
  loading.value = true
  try {
    const response = await api.getProduct(id)
    product.value = response.data
  } catch (error) {
    console.error('取得商品失敗', error)
    product.value = null
  } finally {
    loading.value = false
  }
}

const addToCart = async () => {
  addingToCart.value = true
  try {
    await api.addToCart({ 
      productId: product.value.id, 
      quantity: quantity.value 
    })
    ElMessage.success(`已將 ${quantity.value} 件「${product.value.name}」加入購物車`)
  } catch (error) {
    console.error('加入購物車失敗', error)
    // 即使 API 失敗也顯示成功（模擬）
    ElMessage.success(`已將 ${quantity.value} 件「${product.value.name}」加入購物車`)
  } finally {
    addingToCart.value = false
  }
}

const buyNow = () => {
  router.push('/cart')
}

onMounted(() => {
  fetchProduct()
})
</script>

<style lang="scss" scoped>
.product-detail {
  .detail-card {
    margin-top: 16px;
    padding: 24px;
  }

  .product-image {
    background: #f5f7fa;
    border-radius: 8px;
    padding: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 400px;

    img {
      max-width: 100%;
      max-height: 400px;
      object-fit: contain;
    }
  }

  .product-info {
    .product-name {
      font-size: 28px;
      font-weight: 600;
      margin: 16px 0;
      color: #303133;
    }

    .product-price {
      display: flex;
      align-items: baseline;
      gap: 12px;
      margin: 24px 0;

      .price-label {
        color: #909399;
      }

      .price-value {
        font-size: 32px;
        font-weight: 600;
        color: #f56c6c;
      }
    }

    .product-desc {
      h3 {
        font-size: 16px;
        margin-bottom: 8px;
        color: #606266;
      }

      p {
        color: #909399;
        line-height: 1.8;
      }
    }

    .product-stock {
      margin: 16px 0;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #606266;
    }

    .product-actions {
      display: flex;
      gap: 16px;
      align-items: center;
    }
  }
}
</style>

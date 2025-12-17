<template>
  <div class="product-list">
    <div class="page-header">
      <h1>商品列表</h1>
      <p class="subtitle">瀏覽我們的精選商品</p>
    </div>

    <!-- 搜尋列 -->
    <el-card class="search-card" shadow="never">
      <el-row :gutter="16" align="middle">
        <el-col :span="14">
          <el-input
            v-model="searchKeyword"
            placeholder="搜尋商品名稱... (漏洞模式下可嘗試 SQL 注入: ' OR '1'='1)"
            size="large"
            :prefix-icon="Search"
            @keyup.enter="handleSearch"
            clearable
          />
        </el-col>
        <el-col :span="3">
          <el-button type="primary" size="large" @click="handleSearch" :loading="loading">
            搜尋
          </el-button>
        </el-col>
        <el-col :span="4">
          <el-select v-model="selectedCategory" placeholder="分類" size="large" clearable>
            <el-option label="全部" value="" />
            <el-option label="電子產品" value="電子產品" />
            <el-option label="服飾" value="服飾" />
            <el-option label="書籍" value="書籍" />
          </el-select>
        </el-col>
        <el-col :span="3">
          <el-select v-model="sortBy" placeholder="排序" size="large">
            <el-option label="名稱" value="name" />
            <el-option label="價格" value="price" />
            <el-option label="庫存" value="stock" />
          </el-select>
        </el-col>
      </el-row>
    </el-card>

    <!-- SQL 查詢顯示（教學用） -->
    <el-alert 
      v-if="executedQuery" 
      type="warning" 
      :closable="false" 
      class="query-alert"
      show-icon
    >
      <template #title>
        <span>🔍 執行的 SQL 查詢（僅在漏洞模式顯示）</span>
      </template>
      <code class="sql-query">{{ executedQuery }}</code>
    </el-alert>

    <!-- 商品列表 -->
    <div class="products-grid" v-loading="loading">
      <el-empty v-if="products.length === 0 && !loading" description="沒有找到商品" />
      
      <el-row :gutter="24" v-else>
        <el-col :span="6" v-for="product in products" :key="product.id">
          <el-card shadow="hover" class="product-card" @click="goToDetail(product.id)">
            <div class="product-image">
              <img :src="product.imageUrl || '/placeholder.jpg'" :alt="product.name" />
            </div>
            <div class="product-info">
              <!-- ⚠️ XSS 漏洞：使用 v-html 直接渲染未過濾的 HTML -->
              <h3 class="product-name" v-html="product.name"></h3>
              <p class="product-category">{{ product.category }}</p>
              <div class="product-footer">
                <span class="product-price">NT$ {{ product.price }}</span>
                <el-tag v-if="product.stock > 0" type="success" size="small">有庫存</el-tag>
                <el-tag v-else type="info" size="small">缺貨中</el-tag>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 分頁 -->
    <div class="pagination-wrapper">
      <el-pagination
        v-model:current-page="currentPage"
        :page-size="pageSize"
        :total="total"
        layout="total, prev, pager, next"
        @current-change="handlePageChange"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const router = useRouter()

const loading = ref(false)
const products = ref([])
const searchKeyword = ref('')
const selectedCategory = ref('')
const sortBy = ref('name')
const currentPage = ref(1)
const pageSize = ref(12)
const total = ref(0)
const executedQuery = ref('')

const fetchProducts = async () => {
  loading.value = true
  executedQuery.value = ''
  
  try {
    // 使用漏洞版 searchProducts API（會暴露 SQL）
    const response = await api.searchProductsVuln({
      keyword: searchKeyword.value || '',
      category: selectedCategory.value || undefined,
      sortBy: sortBy.value,
      order: 'asc'
    })
    
    // 漏洞版回傳 { query, count, results }
    if (response.data.query) {
      // 顯示執行的 SQL（教學用）
      executedQuery.value = response.data.query
    }
    
    if (response.data.results) {
      // 漏洞版：將陣列結果轉為物件
      products.value = response.data.results.map(row => ({
        id: row[0],
        name: row[1],
        description: row[2],
        price: row[3],
        stock: row[4],
        category: row[5],
        imageUrl: row[6],
        active: row[7]
      }))
      total.value = response.data.count
    } else if (response.data.content) {
      // 安全版：標準分頁回應
      products.value = response.data.content
      total.value = response.data.totalElements
    } else if (Array.isArray(response.data)) {
      products.value = response.data
      total.value = response.data.length
    } else {
      products.value = []
      total.value = 0
    }
  } catch (error) {
    console.error('搜尋失敗', error)
    // 顯示錯誤訊息（可能包含 SQL 錯誤 - 教學用）
    if (error.response?.data?.detail) {
      ElMessage.error(`搜尋錯誤: ${error.response.data.detail}`)
      executedQuery.value = `錯誤: ${error.response.data.detail}`
    }
    products.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  currentPage.value = 1
  fetchProducts()
}

const handlePageChange = (page) => {
  currentPage.value = page
  fetchProducts()
}

const goToDetail = (id) => {
  router.push(`/products/${id}`)
}

onMounted(() => {
  fetchProducts()
})
</script>

<style lang="scss" scoped>
.product-list {
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

.search-card {
  margin-bottom: 24px;
}

.query-alert {
  margin-bottom: 24px;
  
  .sql-query {
    display: block;
    margin-top: 8px;
    padding: 12px;
    background: #1e1e1e;
    color: #67c23a;
    border-radius: 4px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    white-space: pre-wrap;
    word-break: break-all;
  }
}

.products-grid {
  min-height: 400px;
}

.product-card {
  margin-bottom: 24px;
  cursor: pointer;
  transition: transform 0.3s;

  &:hover {
    transform: translateY(-4px);
  }

  .product-image {
    height: 180px;
    background: #f5f7fa;
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 12px;
    overflow: hidden;

    img {
      max-width: 100%;
      max-height: 100%;
      object-fit: cover;
    }
  }

  .product-info {
    .product-name {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 4px;
      color: #303133;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .product-category {
      font-size: 12px;
      color: #909399;
      margin-bottom: 12px;
    }

    .product-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;

      .product-price {
        font-size: 18px;
        font-weight: 600;
        color: #f56c6c;
      }
    }
  }
}

.pagination-wrapper {
  display: flex;
  justify-content: center;
  margin-top: 32px;
}
</style>

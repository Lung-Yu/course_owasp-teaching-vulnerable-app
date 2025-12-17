<template>
  <div class="product-manage">
    <div class="page-header">
      <h1>商品管理</h1>
      <el-button type="primary" @click="handleAdd">
        <el-icon><Plus /></el-icon>
        新增商品
      </el-button>
    </div>

    <el-card>
      <!-- 搜尋列 -->
      <el-row :gutter="16" class="search-row">
        <el-col :span="8">
          <el-input v-model="searchKeyword" placeholder="搜尋商品名稱" clearable />
        </el-col>
        <el-col :span="4">
          <el-select v-model="searchCategory" placeholder="分類" clearable>
            <el-option label="電子產品" value="electronics" />
            <el-option label="服飾" value="clothing" />
            <el-option label="書籍" value="books" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="handleSearch">搜尋</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-col>
      </el-row>

      <!-- 表格 -->
      <el-table :data="products" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="商品名稱" min-width="150" />
        <el-table-column prop="category" label="分類" width="120" />
        <el-table-column prop="price" label="價格" width="120">
          <template #default="{ row }">
            NT$ {{ row.price }}
          </template>
        </el-table-column>
        <el-table-column prop="stock" label="庫存" width="100">
          <template #default="{ row }">
            <el-tag :type="row.stock > 0 ? 'success' : 'danger'" size="small">
              {{ row.stock }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="active" label="狀態" width="100">
          <template #default="{ row }">
            <el-tag :type="row.active ? 'success' : 'info'" size="small">
              {{ row.active ? '上架' : '下架' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" text @click="handleEdit(row)">編輯</el-button>
            <el-button type="danger" size="small" text @click="handleDelete(row)">刪除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新增/編輯對話框 -->
    <el-dialog v-model="dialogVisible" :title="isEdit ? '編輯商品' : '新增商品'" width="500px">
      <el-form :model="form" :rules="rules" ref="formRef" label-width="80px">
        <el-form-item label="名稱" prop="name">
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item label="分類" prop="category">
          <el-select v-model="form.category" style="width: 100%">
            <el-option label="電子產品" value="electronics" />
            <el-option label="服飾" value="clothing" />
            <el-option label="書籍" value="books" />
          </el-select>
        </el-form-item>
        <el-form-item label="價格" prop="price">
          <el-input-number v-model="form.price" :min="0" style="width: 100%" />
        </el-form-item>
        <el-form-item label="庫存" prop="stock">
          <el-input-number v-model="form.stock" :min="0" style="width: 100%" />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input v-model="form.description" type="textarea" :rows="3" />
        </el-form-item>
        <el-form-item label="狀態">
          <el-switch v-model="form.active" active-text="上架" inactive-text="下架" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSubmit" :loading="submitting">確定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const submitting = ref(false)
const dialogVisible = ref(false)
const isEdit = ref(false)
const formRef = ref()

const searchKeyword = ref('')
const searchCategory = ref('')

const products = ref([])

const form = reactive({
  id: null,
  name: '',
  category: '',
  price: 0,
  stock: 0,
  description: '',
  imageUrl: '',
  active: true,
})

const rules = {
  name: [{ required: true, message: '請輸入商品名稱', trigger: 'blur' }],
  category: [{ required: true, message: '請選擇分類', trigger: 'change' }],
  price: [{ required: true, message: '請輸入價格', trigger: 'blur' }],
}

const fetchProducts = async () => {
  loading.value = true
  try {
    const response = await api.adminGetProducts()
    products.value = Array.isArray(response.data) ? response.data : []
  } catch (error) {
    console.error('取得商品失敗', error)
    ElMessage.error('取得商品列表失敗')
    products.value = []
  } finally {
    loading.value = false
  }
}

const handleSearch = async () => {
  if (!searchKeyword.value && !searchCategory.value) {
    fetchProducts()
    return
  }
  
  loading.value = true
  try {
    const response = await api.searchProducts(searchKeyword.value)
    let result = Array.isArray(response.data) ? response.data : []
    
    // 前端過濾分類
    if (searchCategory.value) {
      result = result.filter(p => p.category === searchCategory.value)
    }
    products.value = result
  } catch (error) {
    console.error('搜尋失敗', error)
    ElMessage.error('搜尋失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

const handleReset = () => {
  searchKeyword.value = ''
  searchCategory.value = ''
  fetchProducts()
}

const handleAdd = () => {
  isEdit.value = false
  Object.assign(form, { id: null, name: '', category: '', price: 0, stock: 0, description: '', imageUrl: '', active: true })
  dialogVisible.value = true
}

const handleEdit = (row) => {
  isEdit.value = true
  Object.assign(form, row)
  dialogVisible.value = true
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm('確定要刪除此商品嗎？', '警告', {
      type: 'warning',
    })
    
    await api.adminDeleteProduct(row.id)
    ElMessage.success('刪除成功')
    fetchProducts()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('刪除失敗: ' + (error.response?.data?.error || error.message))
    }
  }
}

const handleSubmit = async () => {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    if (isEdit.value) {
      await api.adminUpdateProduct(form.id, form)
      ElMessage.success('更新成功')
    } else {
      await api.adminCreateProduct(form)
      ElMessage.success('新增成功')
    }
    dialogVisible.value = false
    fetchProducts()
  } catch (error) {
    ElMessage.error('操作失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  fetchProducts()
})
</script>

<style lang="scss" scoped>
.product-manage {
  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;

    h1 {
      font-size: 24px;
      margin: 0;
    }
  }

  .search-row {
    margin-bottom: 16px;
  }
}
</style>

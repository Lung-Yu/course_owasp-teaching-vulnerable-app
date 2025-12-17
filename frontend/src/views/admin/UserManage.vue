<template>
  <div class="user-manage">
    <div class="page-header">
      <h1>會員管理</h1>
    </div>

    <!-- 搜尋區塊 (A03 HQL Injection) -->
    <el-card class="search-card">
      <el-row :gutter="16" align="middle">
        <el-col :span="10">
          <el-input
            v-model="searchQuery"
            placeholder="搜尋使用者... (漏洞模式可嘗試: admin' OR '1'='1)"
            clearable
            @keyup.enter="handleSearch"
          />
        </el-col>
        <el-col :span="6">
          <el-select v-model="searchField" placeholder="搜尋欄位">
            <el-option label="使用者名稱" value="username" />
            <el-option label="電子郵件" value="email" />
            <el-option label="姓名" value="fullName" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="handleSearch" :loading="searchLoading">搜尋</el-button>
          <el-button @click="resetSearch">重置</el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- HQL 查詢顯示（教學用） -->
    <el-alert 
      v-if="executedQuery" 
      type="warning" 
      :closable="false" 
      class="query-alert"
      show-icon
    >
      <template #title>
        <span>🔍 執行的 HQL 查詢（僅在漏洞模式顯示）</span>
      </template>
      <code class="sql-query">{{ executedQuery }}</code>
    </el-alert>

    <el-card>
      <el-table :data="users" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" label="帳號" width="120" />
        <el-table-column prop="fullName" label="姓名" width="120" />
        <el-table-column prop="email" label="電子郵件" min-width="180" />
        <el-table-column prop="password" label="密碼（漏洞）" width="140" v-if="showPassword">
          <template #default="{ row }">
            <el-tag type="danger" size="small">{{ row.password ? '已洩露' : '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="role" label="角色" width="100">
          <template #default="{ row }">
            <el-tag :type="row.role === 'ADMIN' ? 'danger' : 'primary'" size="small">
              {{ row.role === 'ADMIN' ? '管理員' : '一般會員' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="狀態" width="100">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
              {{ row.enabled ? '啟用' : '停用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="註冊時間" width="160" />
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" text @click="handleEdit(row)">編輯</el-button>
            <el-button :type="row.enabled ? 'warning' : 'success'" size="small" text @click="handleToggleStatus(row)">
              {{ row.enabled ? '停用' : '啟用' }}
            </el-button>
            <el-button type="danger" size="small" text @click="handleDelete(row)">刪除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const searchLoading = ref(false)
const users = ref([])
const searchQuery = ref('')
const searchField = ref('username')
const executedQuery = ref('')
const showPassword = ref(false)

const fetchUsers = async () => {
  loading.value = true
  try {
    const response = await api.adminGetUsers()
    users.value = Array.isArray(response.data) ? response.data : (response.data.users || [])
    executedQuery.value = ''
    showPassword.value = false
  } catch (error) {
    console.error('取得使用者失敗', error)
    ElMessage.error('取得使用者列表失敗')
    users.value = []
  } finally {
    loading.value = false
  }
}

const handleSearch = async () => {
  if (!searchQuery.value) {
    fetchUsers()
    return
  }
  
  searchLoading.value = true
  executedQuery.value = ''
  
  try {
    // 使用漏洞版搜尋 API（會有 HQL Injection）
    const response = await api.searchUsersVuln({
      query: searchQuery.value,
      field: searchField.value
    })
    
    // 顯示執行的 HQL 查詢（教學用）
    if (response.data.query) {
      executedQuery.value = response.data.query
    }
    
    // 漏洞版會回傳密碼
    if (response.data.users) {
      users.value = response.data.users
      showPassword.value = response.data.users.some(u => u.password)
    } else if (Array.isArray(response.data)) {
      users.value = response.data
    }
  } catch (error) {
    console.error('搜尋失敗', error)
    if (error.response?.data?.detail) {
      ElMessage.error(`搜尋錯誤: ${error.response.data.detail}`)
      executedQuery.value = `錯誤: ${error.response.data.detail}`
    }
  } finally {
    searchLoading.value = false
  }
}

const resetSearch = () => {
  searchQuery.value = ''
  searchField.value = 'username'
  executedQuery.value = ''
  showPassword.value = false
  fetchUsers()
}

const handleEdit = async (row) => {
  ElMessageBox.prompt('請輸入新角色 (USER 或 ADMIN)', '修改角色', {
    confirmButtonText: '確定',
    cancelButtonText: '取消',
    inputValue: row.role,
    inputPattern: /^(USER|ADMIN)$/,
    inputErrorMessage: '角色必須是 USER 或 ADMIN'
  }).then(async ({ value }) => {
    try {
      await api.adminUpdateUserRole(row.id, value)
      ElMessage.success('角色更新成功')
      fetchUsers()
    } catch (error) {
      ElMessage.error('更新失敗: ' + (error.response?.data?.error || error.message))
    }
  }).catch(() => {})
}

const handleToggleStatus = async (row) => {
  try {
    if (row.enabled) {
      await api.adminDisableUser(row.id)
      ElMessage.success('使用者已停用')
    } else {
      await api.adminEnableUser(row.id)
      ElMessage.success('使用者已啟用')
    }
    fetchUsers()
  } catch (error) {
    ElMessage.error('操作失敗: ' + (error.response?.data?.error || error.message))
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm('確定要刪除此使用者嗎？', '警告', {
      confirmButtonText: '確定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    await api.adminDeleteUser(row.id)
    ElMessage.success('刪除成功')
    fetchUsers()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('刪除失敗: ' + (error.response?.data?.error || error.message))
    }
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<style lang="scss" scoped>
.user-manage {
  .page-header {
    margin-bottom: 24px;

    h1 {
      font-size: 24px;
      margin: 0;
    }
  }
  
  .search-card {
    margin-bottom: 16px;
  }
  
  .query-alert {
    margin-bottom: 16px;
    
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
}
</style>

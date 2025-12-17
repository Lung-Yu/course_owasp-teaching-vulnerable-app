<template>
  <div class="order-manage">
    <div class="page-header">
      <h1>訂單管理</h1>
    </div>

    <el-card>
      <el-table :data="orders" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="orderNumber" label="訂單編號" width="180" />
        <el-table-column prop="username" label="會員" width="120" />
        <el-table-column prop="totalAmount" label="金額" width="120">
          <template #default="{ row }">
            NT$ {{ row.totalAmount }}
          </template>
        </el-table-column>
        <el-table-column prop="status" label="狀態" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="建立時間" width="160" />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" text @click="handleView(row)">查看</el-button>
            <el-button type="success" size="small" text @click="handleUpdateStatus(row)">更新狀態</el-button>
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
const orders = ref([])

const fetchOrders = async () => {
  loading.value = true
  try {
    const response = await api.adminGetOrders()
    orders.value = Array.isArray(response.data) ? response.data : (response.data.orders || [])
  } catch (error) {
    console.error('取得訂單失敗', error)
    ElMessage.error('取得訂單列表失敗')
    orders.value = []
  } finally {
    loading.value = false
  }
}

const getStatusType = (status) => {
  const map = {
    PENDING: 'warning',
    CONFIRMED: 'primary',
    SHIPPED: 'success',
    DELIVERED: 'success',
    CANCELLED: 'info',
  }
  return map[status] || 'info'
}

const getStatusText = (status) => {
  const map = {
    PENDING: '待處理',
    CONFIRMED: '已確認',
    SHIPPED: '已出貨',
    DELIVERED: '已送達',
    CANCELLED: '已取消',
  }
  return map[status] || status
}

const handleView = (row) => {
  ElMessageBox.alert(
    `<div>
      <p><strong>訂單編號：</strong>${row.orderNumber}</p>
      <p><strong>會員：</strong>${row.username}</p>
      <p><strong>金額：</strong>NT$ ${row.totalAmount}</p>
      <p><strong>狀態：</strong>${getStatusText(row.status)}</p>
      <p><strong>收件地址：</strong>${row.shippingAddress || '無'}</p>
      <p><strong>備註：</strong>${row.note || '無'}</p>
    </div>`,
    '訂單詳情',
    {
      dangerouslyUseHTMLString: true,
      confirmButtonText: '確定'
    }
  )
}

const handleUpdateStatus = async (row) => {
  const statuses = ['PENDING', 'CONFIRMED', 'SHIPPED', 'DELIVERED', 'CANCELLED']
  
  ElMessageBox.prompt('請輸入新狀態', '更新訂單狀態', {
    confirmButtonText: '確定',
    cancelButtonText: '取消',
    inputValue: row.status,
    inputPattern: new RegExp(`^(${statuses.join('|')})$`),
    inputErrorMessage: `狀態必須是: ${statuses.join(', ')}`
  }).then(async ({ value }) => {
    try {
      await api.updateOrderStatus(row.id, value)
      ElMessage.success('狀態更新成功')
      fetchOrders()
    } catch (error) {
      // 顯示後端回傳的警告訊息（A04 工作流程繞過演示）
      const data = error.response?.data
      if (data?.warning) {
        ElMessage.warning(data.warning)
      }
      ElMessage.error('更新失敗: ' + (data?.error || error.message))
    }
  }).catch(() => {})
}

onMounted(() => {
  fetchOrders()
})
</script>

<style lang="scss" scoped>
.order-manage {
  .page-header {
    margin-bottom: 24px;

    h1 {
      font-size: 24px;
      margin: 0;
    }
  }
}
</style>

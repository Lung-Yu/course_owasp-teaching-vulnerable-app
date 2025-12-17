<template>
  <div class="register-page">
    <el-card class="register-card">
      <template #header>
        <div class="card-header">
          <h2>會員註冊</h2>
        </div>
      </template>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        @submit.prevent="handleRegister"
      >
        <el-form-item label="帳號" prop="username">
          <el-input
            v-model="form.username"
            placeholder="請輸入帳號（4-20字元）"
            :prefix-icon="User"
            size="large"
          />
        </el-form-item>

        <el-form-item label="電子郵件" prop="email">
          <el-input
            v-model="form.email"
            placeholder="請輸入電子郵件"
            :prefix-icon="Message"
            size="large"
          />
        </el-form-item>

        <el-form-item label="密碼" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="請輸入密碼（至少6字元）"
            :prefix-icon="Lock"
            size="large"
            show-password
          />
        </el-form-item>

        <el-form-item label="確認密碼" prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            type="password"
            placeholder="請再次輸入密碼"
            :prefix-icon="Lock"
            size="large"
            show-password
          />
        </el-form-item>

        <el-form-item label="姓名" prop="fullName">
          <el-input
            v-model="form.fullName"
            placeholder="請輸入姓名"
            size="large"
          />
        </el-form-item>

        <el-form-item>
          <el-checkbox v-model="form.agreeTerms">
            我已閱讀並同意 <el-link type="primary">服務條款</el-link>
          </el-checkbox>
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            native-type="submit"
            class="register-btn"
          >
            註冊
          </el-button>
        </el-form-item>
      </el-form>

      <div class="register-footer">
        <span>已經有帳號了？</span>
        <el-link type="primary" @click="router.push('/auth/login')">立即登入</el-link>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { User, Lock, Message } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '@/api'

const router = useRouter()

const formRef = ref()
const loading = ref(false)

const form = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  fullName: '',
  agreeTerms: false,
})

const validateConfirmPassword = (rule, value, callback) => {
  if (value !== form.password) {
    callback(new Error('兩次輸入的密碼不一致'))
  } else {
    callback()
  }
}

const rules = {
  username: [
    { required: true, message: '請輸入帳號', trigger: 'blur' },
    { min: 4, max: 20, message: '帳號長度需為 4-20 字元', trigger: 'blur' },
  ],
  email: [
    { required: true, message: '請輸入電子郵件', trigger: 'blur' },
    { type: 'email', message: '請輸入有效的電子郵件', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '請輸入密碼', trigger: 'blur' },
    { min: 6, message: '密碼長度至少 6 字元', trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: '請確認密碼', trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' },
  ],
  fullName: [{ required: true, message: '請輸入姓名', trigger: 'blur' }],
}

const handleRegister = async () => {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  if (!form.agreeTerms) {
    ElMessage.warning('請先同意服務條款')
    return
  }

  loading.value = true
  try {
    await api.register({
      username: form.username,
      email: form.email,
      password: form.password,
      fullName: form.fullName
    })
    
    ElMessage.success('註冊成功，請登入')
    router.push('/auth/login')
  } catch (error) {
    const errorMsg = error.response?.data?.error || error.response?.data?.message || '註冊失敗，請稍後再試'
    ElMessage.error(errorMsg)
  } finally {
    loading.value = false
  }
}
</script>

<style lang="scss" scoped>
.register-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.register-card {
  width: 100%;
  max-width: 480px;

  .card-header {
    h2 {
      margin: 0;
      font-size: 24px;
    }
  }

  .register-btn {
    width: 100%;
  }

  .register-footer {
    text-align: center;
    color: #909399;

    .el-link {
      margin-left: 4px;
    }
  }
}
</style>

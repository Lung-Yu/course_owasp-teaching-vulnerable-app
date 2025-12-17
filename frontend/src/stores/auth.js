import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * 認證 Store
 * 管理使用者登入狀態
 */
export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || null)
  const user = ref(JSON.parse(localStorage.getItem('user') || 'null'))
  
  const isLoggedIn = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.role === 'ADMIN')
  
  function setAuth(authData) {
    token.value = authData.token
    user.value = {
      username: authData.username,
      role: authData.role
    }
    localStorage.setItem('token', authData.token)
    localStorage.setItem('user', JSON.stringify(user.value))
  }
  
  function logout() {
    token.value = null
    user.value = null
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  }
  
  return {
    token,
    user,
    isLoggedIn,
    isAdmin,
    setAuth,
    logout
  }
})

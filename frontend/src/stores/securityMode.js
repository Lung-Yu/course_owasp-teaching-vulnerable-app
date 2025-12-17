import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * 安全模式 Store
 * 管理漏洞模式與安全模式的切換
 */
export const useSecurityModeStore = defineStore('securityMode', () => {
  // 模式類型: 'vulnerable' | 'secure'
  const mode = ref(localStorage.getItem('securityMode') || 'vulnerable')
  
  // API 狀態
  const apiStatus = ref(null)
  const isLoading = ref(false)
  
  // 計算屬性
  const isVulnerable = computed(() => mode.value === 'vulnerable')
  const isSecure = computed(() => mode.value === 'secure')
  
  const modeLabel = computed(() => {
    return mode.value === 'vulnerable' ? '🔓 漏洞模式' : '🔒 安全模式'
  })
  
  const modeDescription = computed(() => {
    return mode.value === 'vulnerable' 
      ? '此模式展示 OWASP Top 10 弱點，僅供教學使用'
      : '此模式已修復所有安全漏洞，展示正確的實作方式'
  })
  
  // API 基礎路徑（透過 nginx 代理）
  const apiBasePath = computed(() => {
    return mode.value === 'vulnerable' ? '/api/vulnerable' : '/api/secure'
  })
  
  // 切換模式
  function toggleMode() {
    mode.value = mode.value === 'vulnerable' ? 'secure' : 'vulnerable'
    localStorage.setItem('securityMode', mode.value)
    apiStatus.value = null // 清除舊狀態
  }
  
  // 設定模式
  function setMode(newMode) {
    if (newMode === 'vulnerable' || newMode === 'secure') {
      mode.value = newMode
      localStorage.setItem('securityMode', mode.value)
      apiStatus.value = null
    }
  }
  
  // 設定 API 狀態
  function setApiStatus(status) {
    apiStatus.value = status
  }
  
  return {
    mode,
    apiStatus,
    isLoading,
    isVulnerable,
    isSecure,
    modeLabel,
    modeDescription,
    apiBasePath,
    toggleMode,
    setMode,
    setApiStatus
  }
})

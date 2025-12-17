import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/vulnerable'

const createApiClient = () => {
  const client = axios.create({
    baseURL: API_BASE_URL,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json',
    },
  })

  client.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem('token')
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )

  client.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response) {
        switch (error.response.status) {
          case 401:
            localStorage.removeItem('token')
            localStorage.removeItem('user')
            window.location.href = '/auth/login'
            break
          case 403:
            console.error('Forbidden')
            break
          case 500:
            console.error('Server error')
            break
        }
      }
      return Promise.reject(error)
    }
  )

  return client
}

const apiClient = createApiClient()

export default {
  getStatus: () => apiClient.get('/status'),
  getHealth: () => apiClient.get('/status/health'),

  login: (data) => apiClient.post('/auth/login', data),
  register: (data) => apiClient.post('/auth/register', data),
  forgotPassword: (data) => apiClient.post('/auth/forgot-password', data),
  resetPassword: (data) => apiClient.post('/auth/reset-password', data),
  changePassword: (data) => apiClient.post('/auth/change-password', data),

  getProducts: (params) => apiClient.get('/products', { params }),
  getProduct: (id) => apiClient.get(`/products/${id}`),
  searchProducts: (keyword) => apiClient.get('/products/search', { params: { keyword } }),

  getUsers: () => apiClient.get('/users'),
  getUser: (id) => apiClient.get(`/users/${id}`),
  updateUser: (id, data) => apiClient.put(`/users/${id}`, data),
  deleteUser: (id) => apiClient.delete(`/users/${id}`),

  getOrders: () => apiClient.get('/orders'),
  getOrder: (id) => apiClient.get(`/orders/${id}`),
  getOrderByNumber: (orderNumber) => apiClient.get(`/orders/number/${orderNumber}`),
  createOrder: (data) => apiClient.post('/orders', data),
  checkout: (data) => apiClient.post('/orders/checkout', data),
  updateOrderStatus: (id, status) => apiClient.put(`/orders/${id}/status`, { status }),
  requestRefund: (id, data) => apiClient.post(`/orders/${id}/refund`, data),

  adminGetStats: () => apiClient.get('/admin/stats'),
  adminGetConfig: () => apiClient.get('/admin/config'),

  adminGetProducts: () => apiClient.get('/products'),
  adminCreateProduct: (data) => apiClient.post('/products', data),
  adminUpdateProduct: (id, data) => apiClient.put(`/products/${id}`, data),
  adminDeleteProduct: (id) => apiClient.delete(`/products/${id}`),

  adminGetUsers: () => apiClient.get('/admin/users'),
  adminGetUser: (id) => apiClient.get(`/users/${id}`),
  adminUpdateUser: (id, data) => apiClient.put(`/users/${id}`, data),
  adminDeleteUser: (id) => apiClient.delete(`/users/${id}`),
  adminUpdateUserRole: (id, role) => apiClient.post(`/admin/users/${id}/role`, { role }),
  adminDisableUser: (id) => apiClient.post(`/admin/users/${id}/disable`),
  adminEnableUser: (id) => apiClient.post(`/admin/users/${id}/enable`),
  adminExportUsers: () => apiClient.get('/admin/export/users'),

  adminGetOrders: () => apiClient.get('/orders'),
  adminUpdateOrder: (id, data) => apiClient.put(`/orders/${id}`, data),

  getFiles: (path) => apiClient.get('/files/list', { params: { path } }),
  downloadFile: (filename) => apiClient.get('/files/download', { params: { filename }, responseType: 'blob' }),
  readFile: (filename) => apiClient.get('/files/read', { params: { filename } }),
  uploadFile: (formData) => apiClient.post('/files/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } }),

  search: (params) => apiClient.get('/search', { params }),
  advancedSearch: (params) => apiClient.get('/search/advanced', { params }),
  searchProductsVuln: (params) => apiClient.get('/search/products', { params }),
  searchUsersVuln: (params) => apiClient.get('/search/users', { params }),
  searchOrdersVuln: (params) => apiClient.get('/search/orders', { params }),
  generateReport: (data) => apiClient.post('/search/report', data),
  getTableInfo: (schema) => apiClient.get('/search/tables', { params: { schema } }),

  systemPing: (host) => apiClient.get('/system/ping', { params: { host } }),
  systemLookup: (domain) => apiClient.get('/system/lookup', { params: { domain } }),
  systemInfo: (cmd) => apiClient.get('/system/info', { params: { cmd } }),
  systemReadLog: (filename) => apiClient.get('/system/read-log', { params: { filename } }),
  systemDiagnose: (data) => apiClient.post('/system/diagnose', data),

  templateEval: (expression) => apiClient.get('/template/eval', { params: { expression } }),
  templateRender: (data) => apiClient.post('/template/render', data),

  cryptoEncrypt: (data) => apiClient.post('/crypto/encrypt', data),
  cryptoDecrypt: (data) => apiClient.post('/crypto/decrypt', data),
  cryptoHash: (data) => apiClient.post('/crypto/hash', data),
  cryptoGenerateToken: () => apiClient.post('/crypto/generate-token'),
  cryptoTokenHistory: () => apiClient.get('/crypto/token-history'),

  getCart: () => apiClient.get('/orders/cart'),
  addToCart: (data) => apiClient.post('/orders/cart', data),
  updateCartItem: (itemId, data) => apiClient.put(`/orders/cart/${itemId}`, data),
  removeFromCart: (itemId) => apiClient.delete(`/orders/cart/${itemId}`),

  integritySaveCart: (data) => apiClient.post('/integrity/cart/save', data),
  integrityCheckout: (data) => apiClient.post('/integrity/cart/checkout', data),

  xmlParse: (data) => apiClient.post('/xml/parse', data),
  xmlImportSettings: (data) => apiClient.post('/xml/import-settings', data),

  getDebugConfig: () => apiClient.get('/debug/config'),
  getDebugEnv: () => apiClient.get('/debug/env'),

  testWebhook: (url) => apiClient.post('/webhook/test', null, { params: { url } }),
  fetchUrl: (url) => apiClient.get('/webhook/fetch', { params: { url } }),

  getCoupons: () => apiClient.get('/coupons/available'),
  applyCoupon: (data) => apiClient.post('/coupons/apply', data),
  validateCoupon: (code) => apiClient.post('/coupons/validate', { code }),

  getFlashSales: () => apiClient.get('/flash-sale/active'),
  buyFlashSale: (flashSaleId, quantity = 1) => apiClient.post('/flash-sale/buy', { flashSaleId, quantity }),
  rapidBuyFlashSale: (flashSaleId, times) => apiClient.post('/flash-sale/rapid-buy', { flashSaleId, times }),
  resetFlashSale: () => apiClient.post('/flash-sale/reset'),

  getAuditLogs: () => apiClient.get('/logging/view/audit'),
  getLoginAttempts: () => apiClient.get('/logging/view/login-attempts'),
  getSecurityAlerts: () => apiClient.get('/logging/view/alerts'),
}

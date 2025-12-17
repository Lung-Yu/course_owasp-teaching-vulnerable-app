import { createRouter, createWebHistory } from 'vue-router'

// 版面配置
import PublicLayout from '@/layouts/PublicLayout.vue'
import AdminLayout from '@/layouts/AdminLayout.vue'

const routes = [
  // 前台路由
  {
    path: '/',
    component: PublicLayout,
    children: [
      {
        path: '',
        name: 'Home',
        component: () => import('@/views/public/HomePage.vue'),
        meta: { title: '首頁' }
      },
      {
        path: 'products',
        name: 'Products',
        component: () => import('@/views/public/ProductList.vue'),
        meta: { title: '商品列表' }
      },
      {
        path: 'products/:id',
        name: 'ProductDetail',
        component: () => import('@/views/public/ProductDetail.vue'),
        meta: { title: '商品詳情' }
      },
      {
        path: 'cart',
        name: 'Cart',
        component: () => import('@/views/public/CartPage.vue'),
        meta: { title: '購物車' }
      },
      {
        path: 'checkout',
        name: 'Checkout',
        component: () => import('@/views/public/CheckoutPage.vue'),
        meta: { title: '結帳' }
      },
      {
        path: 'flash-sale',
        name: 'FlashSale',
        component: () => import('@/views/public/FlashSale.vue'),
        meta: { title: '限時搶購' }
      },
      {
        path: 'profile',
        name: 'Profile',
        component: () => import('@/views/public/ProfilePage.vue'),
        meta: { title: '會員中心' }
      },
    ]
  },

  // 認證路由
  {
    path: '/auth',
    children: [
      {
        path: 'login',
        name: 'Login',
        component: () => import('@/views/auth/LoginPage.vue'),
        meta: { title: '登入' }
      },
      {
        path: 'register',
        name: 'Register',
        component: () => import('@/views/auth/RegisterPage.vue'),
        meta: { title: '註冊' }
      },
      {
        path: 'forgot-password',
        name: 'ForgotPassword',
        component: () => import('@/views/auth/ForgotPasswordPage.vue'),
        meta: { title: '忘記密碼' }
      },
    ]
  },

  // 後台路由
  {
    path: '/admin',
    component: AdminLayout,
    meta: { requiresAuth: true, requiresAdmin: true },
    children: [
      {
        path: '',
        name: 'AdminDashboard',
        component: () => import('@/views/admin/Dashboard.vue'),
        meta: { title: '管理後台' }
      },
      {
        path: 'products',
        name: 'AdminProducts',
        component: () => import('@/views/admin/ProductManage.vue'),
        meta: { title: '商品管理' }
      },
      {
        path: 'users',
        name: 'AdminUsers',
        component: () => import('@/views/admin/UserManage.vue'),
        meta: { title: '會員管理' }
      },
      {
        path: 'orders',
        name: 'AdminOrders',
        component: () => import('@/views/admin/OrderManage.vue'),
        meta: { title: '訂單管理' }
      },
      {
        path: 'system-tools',
        name: 'AdminSystemTools',
        component: () => import('@/views/admin/SystemTools.vue'),
        meta: { title: '系統工具' }
      },
    ]
  },

  // 404
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue'),
    meta: { title: '頁面不存在' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 路由守衛
router.beforeEach((to, from, next) => {
  // 設定頁面標題
  document.title = to.meta.title 
    ? `${to.meta.title} - OWASP Demo` 
    : 'OWASP Demo - 弱點教學網站'

  // TODO: 後續加入認證檢查
  next()
})

export default router

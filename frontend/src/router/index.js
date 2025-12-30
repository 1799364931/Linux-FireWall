import { createRouter, createWebHistory } from 'vue-router';
import Login from '../pages/Login.vue';
import RuleManage from '../pages/RuleManage.vue';
import SystemManage from '../pages/SystemManage.vue';
import LogMonitor from '../pages/LogMonitor.vue';

const routes = [
  // 登录页
  { path: '/login', name: 'Login', component: Login },
  // 重定向：默认跳登录页
  { path: '/', redirect: '/login' },
  // 规则管理
  { path: '/rule-manage', name: 'RuleManage', component: RuleManage },
  // 系统管理
  { path: '/system-manage', name: 'SystemManage', component: SystemManage },
  // 监控统计
  { path: '/log-monitor', name: 'LogMonitor', component: LogMonitor }
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes
});

// 添加全局路由守卫（未登录不能访问功能页面）=====
router.beforeEach((to, from, next) => {
  const authInfo = localStorage.getItem('firewall_auth');
  const isLoginPage = to.path === '/login';
  // 逻辑：未登录 + 不是登录页 → 跳登录页；否则正常访问
  if (!authInfo && !isLoginPage) {
    next('/login');
  } else {
    next();
  }
});

export default router;
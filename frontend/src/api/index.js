import axios from 'axios';
import { ElMessage, ElMessageBox } from 'element-plus';
import router from '../router'; // 导入路由，用于未登录时跳登录页

const service = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 30000
});

// 请求拦截器：动态添加Basic认证头
service.interceptors.request.use(
  (config) => {
    // 从localStorage获取登录的账号密码
    const authInfo = localStorage.getItem('firewall_auth');
    if (authInfo) {
      const { username, password } = JSON.parse(authInfo);
      // 生成Basic认证的base64编码
      const auth = btoa(`${username}:${password}`);
      config.headers['Authorization'] = `Basic ${auth}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 响应拦截器：处理401未授权
service.interceptors.response.use(
  (res) => {
    if (res.data.code !== 200) {
      ElMessage.error(res.data.message || '请求失败');
      return Promise.reject(res.data);
    }
    return res.data;
  },
  (error) => {
    // 捕获401未授权错误：清除认证信息，跳登录页
    if (error.response?.status === 401) {
      localStorage.removeItem('firewall_auth');
      ElMessageBox.alert('登录已过期，请重新登录', '提示', {
        confirmButtonText: '确定'
      }).then(() => {
        router.push('/login');
      });
    } else {
      ElMessage.error(error.response?.data?.message || error.message);
    }
    return Promise.reject(error);
  }
);

export default service;
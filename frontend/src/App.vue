<template>
  <div v-if="isLoginPage">
    <router-view />
  </div>
  <div v-else class="app-container">
    <!-- 侧边栏：Flex列布局，结构为【项目名称+菜单+退出登录】 -->
    <div class="sidebar">
      <!-- 侧边栏顶部项目名称 -->
      <div class="sidebar-header">
        <span class="project-name">防火墙管理系统</span>
      </div>
      <!-- 菜单部分 -->
      <el-menu 
        :default-active="currentRoutePath" 
        router 
        mode="vertical"
      >
        <el-menu-item index="/rule-manage">
          <el-icon><Setting /></el-icon>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/system-manage">
          <el-icon><Monitor /></el-icon>
          <span>系统管理</span>
        </el-menu-item>
        <el-menu-item index="/log-monitor">
          <el-icon><VideoCamera /></el-icon>
          <span>实时监控</span>
        </el-menu-item>
      </el-menu>
      <!-- 退出登录 -->
      <div class="logout-item" @click="handleLogout">
        <el-icon><UserFilled /></el-icon>
        <span>退出登录</span>
      </div>
    </div>
    <div class="main-content">
      <router-view />
    </div>
  </div>
</template>

<script setup>
import { Setting, Monitor, UserFilled, VideoCamera } from '@element-plus/icons-vue';
import { useRouter, useRoute } from 'vue-router'; 
import { ElMessage, ElMessageBox } from 'element-plus';
import { computed } from 'vue';

const router = useRouter();
const route = useRoute();

const currentRoutePath = computed(() => route.path);
const isLoginPage = computed(() => route.path === '/login' || route.path === '/');

const handleLogout = () => {
  ElMessageBox.confirm('确定退出登录吗？', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(() => {
    localStorage.removeItem('firewall_auth');
    router.push('/login');
    ElMessage.success('退出登录成功');
  }).catch(() => {
    ElMessage.info('已取消退出');
  });
};
</script>

<style scoped>
.app-container {
  display: flex;
  height: 100vh;
}

.sidebar {
  width: 200px;
  background: #2e3b4e;
  color: white;
  display: flex;
  flex-direction: column; 
  height: 100%; 
}

.sidebar-header {
  padding: 0 20px;
  height: 60px; 
  line-height: 60px;
  border-bottom: 1px solid #3a495e; 
  display: flex;
  align-items: center;
}
.project-name {
  font-size: 16px;
  font-weight: 600;
  color: #409eff; 
}

:deep(.el-menu) {
  background-color: #2e3b4e;
  color: white;
  flex: 1; 
  border-right: none; 
  overflow: auto; 
}

.logout-item {
  padding: 0 20px;
  height: 60px; 
  line-height: 60px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  transition: background 0.3s;
  border-top: 1px solid #3a495e; 
}
.logout-item:hover {
  background-color: #1f2d3d; 
}

:deep(.el-menu-item) {
  color: white;
  height: 60px; 
  line-height: 60px;
}
:deep(.el-menu-item:hover) {
  background-color: #1f2d3d;
}
:deep(.el-menu-item.is-active) {
  background-color: #409eff;
  color: white;
}

.main-content {
  flex: 1;
  padding: 20px;
  overflow: auto;
  background-color: #f5f7fa; 
}
</style>
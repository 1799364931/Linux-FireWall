<template>
  <div class="login-container">
    <div class="login-form fade-in">
      <h2 class="login-title">
        防火墙管理系统
        <span class="title-line"></span>
      </h2>
      <!-- label-width为80px -->
      <el-form 
        :model="loginForm" 
        :rules="loginRules" 
        ref="loginFormRef" 
        label-width="80px"
        class="form-content"
      >
        <!-- label="用户名"属性 -->
        <el-form-item label="用户名" prop="username">
          <el-input 
            v-model="loginForm.username" 
            placeholder="请输入用户名"
            prefix-icon="User"
            class="form-input"
          ></el-input>
        </el-form-item>
        <!-- label="密码"属性 -->
        <el-form-item label="密码" prop="password">
          <el-input 
            v-model="loginForm.password" 
            type="password" 
            placeholder="请输入密码"
            prefix-icon="Lock"
            class="form-input"
          ></el-input>
        </el-form-item>
        <el-form-item>
          <el-button 
            type="primary" 
            @click="handleLogin" 
            class="login-btn"
          >
            登录
          </el-button>
        </el-form-item>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { User, Lock } from '@element-plus/icons-vue';

const router = useRouter();
const loginForm = ref({ username: '', password: '' });
const loginRules = ref({
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
});
const loginFormRef = ref(null);

const handleLogin = () => {
  loginFormRef.value.validate((valid) => {
    if (!valid) return;
    const correctUser = 'admin';
    const correctPwd = 'admin123456';
    if (loginForm.value.username === correctUser && loginForm.value.password === correctPwd) {
      localStorage.setItem('firewall_auth', JSON.stringify(loginForm.value));
      ElMessage.success('登录成功！');
      router.push('/system-manage');
    } else {
      ElMessage.error('用户名或密码错误！');
    }
  });
};
</script>

<style scoped>
.login-container {
  width: 100vw;
  height: 100vh;
  background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
  display: flex;
  justify-content: center;
  align-items: center;
  overflow: hidden;
}

.login-form {
  width: 420px; 
  padding: 40px 30px;
  background: #ffffff;
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
  position: relative;
}

.login-title {
  font-size: 22px;
  font-weight: 600;
  color: #1e88e5;
  text-align: center;
  margin-bottom: 30px;
  position: relative;
}
.title-line {
  display: block;
  width: 40px;
  height: 3px;
  background: #1e88e5;
  margin: 8px auto 0;
  border-radius: 2px;
}

.form-content {
  margin-top: 20px;
}

.form-input {
  height: 48px;
  border-radius: 8px;
  border-color: #e0e0e0;
  font-size: 14px;
  transition: all 0.3s ease;
}
.form-input:focus {
  border-color: #1e88e5;
  box-shadow: 0 0 0 2px rgba(30, 136, 229, 0.1);
}

:deep(.el-form-item__label) {
  color: #333;
  font-size: 14px;
  font-weight: 500;
}

.login-btn {
  width: 100%;
  height: 48px;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 500;
  background: #1e88e5;
  border: none;
  transition: all 0.3s ease;
}
.login-btn:hover {
  background: #1976d2;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(30, 136, 229, 0.2);
}

.fade-in {
  animation: fadeIn 0.6s ease forwards;
  opacity: 0;
}
@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
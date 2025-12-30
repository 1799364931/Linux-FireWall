<template>
  <div class="system-manage-container" style="min-height: 80vh; padding: 20px;">
    <h1 class="page-title">系统管理</h1>
    <el-card class="main-card" shadow="hover">
      <!-- 操作区 -->
      <div class="operation-area">
        <h3 class="area-title">防火墙操作</h3>
        <div class="btn-group">
          <el-button 
            type="success" 
            size="default"
            @click="handleStartFirewall"
            :disabled="firewallStatus === '已启动'"
            class="operation-btn start-btn"
          >
            <el-icon><<i-ep-play-circle /></el-icon>
            启动防火墙
          </el-button>
          <el-button 
            type="danger" 
            size="default"
            @click="handleStopFirewall"
            :disabled="firewallStatus === '未启动'"
            class="operation-btn stop-btn"
          >
            <el-icon><<i-ep-stop-circle /></el-icon>
            停止防火墙
          </el-button>
        </div>
      </div>

      <el-divider content-position="left">当前状态</el-divider>

      <!-- 状态区 -->
      <div class="status-area">
        <div class="status-display">
          <el-icon class="status-icon" :color="statusColor">
            <template v-if="firewallStatus === '已启动'">
              <<i-ep-check-circle-filled />
            </template>
            <template v-else-if="firewallStatus === '未启动'">
              <<i-ep-warning-circle-filled />
            </template>
            <template v-else>
              <<i-ep-loading />
            </template>
          </el-icon>
          <span class="status-label">防火墙状态：</span>
          <el-tag :type="statusTagType" size="medium" class="status-tag">
            {{ firewallStatus }}
          </el-tag>
        </div>

        <el-button 
          v-if="firewallStatus === '已启动'" 
          type="primary" 
          size="default"
          @click="goToRuleManage"
          class="goto-btn"
        >
          <el-icon><<i-ep-arrow-right /></el-icon>
          前往规则管理
        </el-button>
      </div>

      <div class="tips-area" v-if="firewallStatus === '已启动'">
        <el-alert 
          title="风险提示" 
          message="停止防火墙将暂停所有规则拦截，导致防护失效，请谨慎操作！" 
          type="warning"  
          size="small" 
          show-icon 
          style="margin-top: 15px;"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue';  
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import service from '@/api/index';

const router = useRouter();
const firewallStatus = ref('加载中...');

// 计算属性
const statusTagType = computed(() => {
  switch (firewallStatus.value) {
    case '已启动':
      return 'success';
    case '未启动':
      return 'warning';
    default:
      return 'info';
  }
});

const statusColor = computed(() => {
  switch (firewallStatus.value) {
    case '已启动':
      return '#67c23a';
    case '未启动':
      return '#e6a23c';
    default:
      return '#409eff';
  }
});

// 获取状态
const getFirewallStatus = async () => {
  try {
    const res = await service({
      url: '/api/system/status',
      method: 'get'
    });
    firewallStatus.value = res.data.is_running ? '已启动' : '未启动';
  } catch (err) {
    ElMessage.error(`获取状态失败：${err.response?.data?.detail || '未知错误'}`);
    firewallStatus.value = '未启动';
  }
};

// 定时器
let statusTimer = null;
onMounted(() => {
  getFirewallStatus();
  statusTimer = setInterval(() => getFirewallStatus(), 5000);
});
onUnmounted(() => clearInterval(statusTimer));

// 启动防火墙
const handleStartFirewall = async () => {
  try {
    const res = await service({ url: '/api/system/start', method: 'post' });
    ElMessage.success(res.message);
    await getFirewallStatus();
  } catch (err) {
    ElMessage.error(`启动失败：${err.response?.data?.detail || '未知错误'}`);
  }
};

// 停止防火墙添加二次确认弹窗
const handleStopFirewall = async () => {
  try {
    // 弹出二次确认框，告知风险并让用户确认
    await ElMessageBox.confirm(
      '停止防火墙将暂停所有规则拦截，导致防护失效，你确定要停止吗？', // 风险提示内容
      '危险操作确认', // 弹窗标题
      {
        confirmButtonText: '确定停止',
        cancelButtonText: '取消',
        type: 'warning', // 弹窗类型
        dangerMode: true // 确认按钮变为红色，强调危险
      }
    );

    // 用户点击“确定停止”后，才执行停止操作
    await service({ url: '/api/system/stop', method: 'post' });
    ElMessage.success('防火墙已成功停止！'); 
    await getFirewallStatus();
  } catch (err) {
    if (err === 'cancel') {
      ElMessage.info('已取消停止防火墙操作');
    } else {
      ElMessage.error(`停止失败：${err.response?.data?.detail || '未知错误'}`);
    }
  }
};

// 前往规则管理
const goToRuleManage = () => router.push('/rule-manage');
</script>

<style scoped>
.page-title {
  font-size: 20px;
  font-weight: 700;
  color: #303133;
  margin: 0 0 20px 0;
}
.main-card {
  border-radius: 8px;
  padding: 25px;
}
.operation-area {
  margin-bottom: 10px;
}
.area-title {
  font-size: 16px;
  font-weight: 600;
  color: #606266;
  margin: 0 0 15px 0;
}
.btn-group {
  display: flex;
  gap: 15px;
}
.operation-btn {
  border-radius: 6px;
  padding: 10px 20px;
  transition: all 0.2s ease;
}
.operation-btn:hover {
  transform: scale(1.02);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
.status-area {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
}
.status-display {
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-icon {
  font-size: 20px;
}
.status-label {
  font-size: 14px;
  color: #606266;
}
.status-tag {
  font-weight: 600;
}
.goto-btn {
  border-radius: 6px;
  padding: 8px 20px;
  transition: all 0.2s ease;
}
.goto-btn:hover {
  transform: scale(1.02);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
.tips-area {
  margin-top: 10px;
}
@media (max-width: 768px) {
  .status-area {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
  }
}
</style>
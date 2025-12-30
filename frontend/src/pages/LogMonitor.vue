<template>
  <div class="log-monitor-container" style="min-height: 80vh; padding: 20px;">
    <h1 class="page-title">实时日志监控</h1>
    <el-card class="main-card" shadow="hover">
      <!-- 操作区 -->
      <div class="operation-area">
        <h3 class="area-title">日志器操作</h3>
        <div class="btn-group">
          <el-button 
            type="success" 
            size="default"
            @click="handleStartLogger"
            :disabled="loggerStatus === '已启动'"
            class="operation-btn start-btn"
          >
            <el-icon><<i-ep-play-circle /></el-icon>
            启动日志器
          </el-button>
          <el-button 
            type="danger" 
            size="default"
            @click="handleStopLogger"
            :disabled="loggerStatus === '未启动'"
            class="operation-btn stop-btn"
          >
            <el-icon><<i-ep-play-circle /></el-icon>
            停止日志器
          </el-button>
          <el-button 
            type="primary" 
            size="default"
            @click="handleClearLogs"
            class="operation-btn clear-btn"
          >
            <el-icon><<i-ep-play-circle /></el-icon>
            清空日志
          </el-button>
        </div>
        <div class="poll-tip" style="margin-top: 10px; font-size: 12px; color: #909399;">
          实时轮询间隔：{{ POLL_INTERVAL }}ms（已优化为增量更新）
        </div>
      </div>

      <!-- 状态区 -->
      <el-divider content-position="left">当前状态</el-divider>
      <div class="status-area">
        <div class="status-display">
          <el-icon class="status-icon" :color="statusColor">
            <template v-if="loggerStatus === '已启动'">
              <i-ep-check-circle-filled />
            </template>
            <template v-else-if="loggerStatus === '未启动'">
              <i-ep-warning-circle-filled />
            </template>
            <template v-else>
              <i-ep-loading />
            </template>
          </el-icon>
          <span class="status-label">日志器状态：</span>
          <el-tag :type="statusTagType" size="default" class="status-tag">
            {{ loggerStatus }}
          </el-tag>
          <span class="log-count">(当前日志条数：{{ logs.length }})</span>
        </div>
      </div>

      <!-- 日志展示区 -->
      <div class="log-area" style="margin-top: 20px;">
        <h3 class="area-title">实时包日志</h3>
        <div class="log-container" v-loading="loading" element-loading-text="加载日志中...">
          <template v-if="logs.length === 0 && loggerStatus === '已启动'">
            <div class="table-empty">
              <el-icon size="40"><Document /></el-icon>
              <p>暂无实时日志数据，请等待数据包触发...</p>
            </div>
          </template>
          <template v-if="logs.length === 0 && loggerStatus === '未启动'">
            <div class="table-empty">
              <el-icon size="40"><Warning /></el-icon>
              <p>日志器未启动，点击「启动日志器」开始监控</p>
              <el-button type="success" size="small" @click="handleStartLogger">启动日志器</el-button>
            </div>
          </template>
          <div 
            class="log-item" 
            v-for="(log, idx) in logs" 
            :key="idx"
            :class="{ 'new-log': idx >= logs.length - newLogCount }"
          >
            {{ log }}
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Document, Warning } from '@element-plus/icons-vue';
import service from '@/api/index';

// 响应式变量
const logs = ref([]);          // 日志列表
const loggerStatus = ref('加载中...'); 
const loading = ref(false);    
let pollTimer = null;          
const POLL_INTERVAL = 60;     // 轮询间隔200ms
const newLogCount = ref(0);    // 记录新增日志数
const lastLogId = ref(0);     // 记录最后一次获取的日志ID

const statusTagType = computed(() => {
  switch (loggerStatus.value) {
    case '已启动': return 'success';
    case '未启动': return 'warning';
    default: return 'info';
  }
});
const statusColor = computed(() => {
  switch (loggerStatus.value) {
    case '已启动': return '#67c23a';
    case '未启动': return '#e6a23c';
    default: return '#409eff';
  }
});

// 获取日志器状态
const getLoggerStatus = async () => {
  try {
    const res = await service({ url: '/api/logger/status', method: 'get' });
    loggerStatus.value = res.data.is_running ? '已启动' : '未启动';
    if (loggerStatus.value === '已启动') {
      startPollLogs();
    }
  } catch (err) {
    ElMessage.error(`获取状态失败：${err.response?.data?.detail || '未知错误'}`);
    loggerStatus.value = '未启动';
  }
};

// 获取日志列表
const getLogs = async () => {
  try {
    const res = await service({ 
      url: '/api/logger/logs/increment', 
      method: 'get',
      params: { last_id: lastLogId.value } // 传入最后一个ID
    });
    const { new_logs, current_max_id } = res.data;
    if (new_logs.length > 0) {
      // 逐条添加新日志
      new_logs.forEach((logItem, idx) => {
        setTimeout(() => {
          logs.value.push(logItem.content);
          // 前端也保持最多200条：删除最旧的一条
          if (logs.value.length > 200) {
            logs.value.shift();
          }
          // 高亮+滚动到底部
          newLogCount.value = 1;
          nextTick(() => {
            const container = document.querySelector('.log-container');
            if (container) container.scrollTop = container.scrollHeight;
          });
          setTimeout(() => {
            newLogCount.value = 0;
          }, 3000);
        }, idx * 250);
      });
      // 更新最后一个ID
      lastLogId.value = current_max_id;
    }
  } catch (err) {
    console.error('获取日志错误：', err);
    ElMessage.error(`获取日志失败：${err.response?.data?.detail || err.message || '未知错误'}`);
  }
};

// 启动轮询
const startPollLogs = () => {
  if (pollTimer) clearInterval(pollTimer);
  // 初始化日志列表和lastLogId
  service({ url: '/api/logger/logs', method: 'get' }).then(res => {
    const logList = res.data.logs;
    // 提取日志内容
    logs.value = logList.map(item => item.content);
    // 记录当前最大ID
    lastLogId.value = logList.length > 0 ? logList[logList.length - 1].id : 0;
  });
  pollTimer = setInterval(getLogs, POLL_INTERVAL);
};

// 停止轮询
const stopPollLogs = () => {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
};

// 启动日志器
const handleStartLogger = async () => {
  try {
    loading.value = true;
    await service({ url: '/api/logger/start', method: 'post' });
    ElMessage.success('日志器启动成功！');
    loggerStatus.value = '已启动';
    startPollLogs();
  } catch (err) {
    ElMessage.error(`启动失败：${err.response?.data?.detail || '未知错误'}`);
  } finally {
    loading.value = false;
  }
};

// 停止日志器
const handleStopLogger = async () => {
  try {
    await ElMessageBox.confirm(
      '停止日志器将终止实时包监控，你确定要停止吗？',
      '操作确认',
      { 
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
        dangerMode: true 
      }
    );
    loading.value = true;
    await service({ url: '/api/logger/stop', method: 'post' });
    ElMessage.success('日志器已停止！');
    loggerStatus.value = '未启动';
    stopPollLogs();
  } catch (err) {
    if (err === 'cancel') {
      ElMessage.info('已取消停止操作');
    } else {
      ElMessage.error(`停止失败：${err.response?.data?.detail || '未知错误'}`);
    }
  } finally {
    loading.value = false;
  }
};

// 清空日志
const handleClearLogs = async () => {
  try {
    await ElMessageBox.confirm(
      '确定清空所有日志吗？清空后不可恢复！',
      '清空确认',
      { 
        type: 'warning',
        confirmButtonText: '确认',
        cancelButtonText: '取消'
      }
    );
    await service({ url: '/api/logger/clear', method: 'post' });
    logs.value = [];
    lastLogId.value = 0; // 重置ID
    newLogCount.value = 0;
    ElMessage.success('日志已清空！');
  } catch (err) {
    if (err === 'cancel') ElMessage.info('已取消清空操作');
    else ElMessage.error(`清空失败：${err.response?.data?.detail || '未知错误'}`);
  }
};

// 生命周期
onMounted(() => {
  getLoggerStatus();
});
onUnmounted(() => {
  stopPollLogs();
});
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
  flex-wrap: wrap;
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
  padding: 10px 0;
}
.status-display {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
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
.log-count {
  font-size: 14px;
  color: #909399;
}
.log-area {
  margin-top: 20px;
}
.log-container {
  height: 400px;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  padding: 15px;
  overflow-y: auto;
  background-color: #f8f9fa;
  --el-loading-text-color: #606266;
  --el-loading-background: rgba(255, 255, 255, 0.8);
}
.log-item {
  padding: 8px 0;
  border-bottom: 1px dashed #e5e5e5;
  font-size: 14px;
  color: #303133;
  line-height: 1.5;
  transition: background-color 0.3s ease;
}
.log-item:last-child {
  border-bottom: none;
}
.new-log {
  background-color: #f0f9ff;
  border-left: 3px solid #409eff;
  padding-left: 10px;
}
.table-empty {
  text-align: center;
  padding: 40px 0;
  color: #909399;
}
.table-empty p {
  margin: 10px 0;
  font-size: 14px;
}
.poll-tip {
  margin-top: 10px;
  font-size: 12px;
  color: #909399;
}
@media (max-width: 768px) {
  .btn-group {
    flex-direction: column;
    gap: 10px;
  }
  .status-display {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .log-container {
    height: 300px;
  }
}
</style>
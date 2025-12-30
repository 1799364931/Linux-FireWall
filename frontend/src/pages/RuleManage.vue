<template>
  <div class="rule-manage-container">
    <!-- 顶部操作栏:优化布局和按钮样式 -->
    <div class="top-actions">
      <el-button type="primary" @click="openForm" class="add-btn" :loading="addLoading">添加规则</el-button>
      <!-- 批量删除按钮 -->
      <el-button 
        type="danger" 
        @click="batchDelRule" 
        class="batch-del-btn"
        :disabled="selectedRows.length === 0"
        icon="el-icon-delete"
      >
        批量删除
      </el-button>
      <!-- 黑白名单筛选按钮组 -->
      <div class="filter-group">
        <el-button-group>
          <el-button 
            @click="currentFilter = '全部'"
            :type="currentFilter === '全部' ? 'primary' : 'default'"
            size="default"
          >
            全部
          </el-button>
          <el-button 
            @click="currentFilter = '黑名单'"
            :type="currentFilter === '黑名单' ? 'primary' : 'default'"
            size="default"
          >
            黑名单
          </el-button>
          <el-button 
            @click="currentFilter = '白名单'"
            :type="currentFilter === '白名单' ? 'primary' : 'default'"
            size="default"
          >
            白名单
          </el-button>
        </el-button-group>
      </div>
      <!-- 新增：出入站筛选按钮组 -->
      <div class="filter-group" style="margin-left: 20px;">
        <el-button-group>
          <el-button 
            @click="currentDirectionFilter = '全部'"
            :type="currentDirectionFilter === '全部' ? 'primary' : 'default'"
            size="default"
          >
            所有方向
          </el-button>
          <el-button 
            @click="currentDirectionFilter = '入站'"
            :type="currentDirectionFilter === '入站' ? 'primary' : 'default'"
            size="default"
          >
            入站
          </el-button>
          <el-button 
            @click="currentDirectionFilter = '出站'"
            :type="currentDirectionFilter === '出站' ? 'primary' : 'default'"
            size="default"
          >
            出站
          </el-button>
        </el-button-group>
      </div>
    </div>
    
    <el-table 
      :data="filteredRules"
      border 
      class="rule-table"
      v-loading="loading"
      element-loading-text="加载规则中..."
      element-loading-background="rgba(255, 255, 255, 0.8)"
      stripe
      :row-class-name="tableRowClassName"
      ref="tableRef"
      @selection-change="handleSelectionChange"
    >
      <!-- 表格多选列 -->
      <el-table-column type="selection" width="55" />

      <!-- 新增：规则方向列 -->
      <el-table-column prop="direction" label="规则方向" width="100">
        <template #default="scope">
          <el-tag 
            :type="scope.row.direction === 'in' ? 'info' : 'warning'"
            class="direction-tag"
          >
            {{ formatDirection(scope.row.direction) }}
          </el-tag>
        </template>
      </el-table-column>

      <!-- 表格空状态自定义插槽 -->
      <template #empty>
        <div class="table-empty">
          <el-icon size="40"><Document /></el-icon>
          <p>暂无规则数据</p>
          <el-button type="primary" size="small" @click="openForm">添加规则</el-button>
        </div>
      </template>

      <!-- 固定显示列:规则ID、动作 -->
      <el-table-column prop="id" label="规则ID" width="80">
        <template #default="scope">
          <div class="rule-id">{{ scope.row.id }}</div>
        </template>
      </el-table-column>
      <el-table-column label="动作" min-width="100">
        <template #default="scope">
          <el-tag 
            :type="scope.row.action === 'accept' ? 'success' : 'danger'"
            class="action-tag"
          >
            {{ formatAction(scope.row.action) }}
          </el-tag>
        </template>
      </el-table-column>

      <!-- 展开列:详情 -->
      <el-table-column type="expand" label="详情" min-width="50">
        <template #default="scope">
          <!-- 先过滤出有值的字段,若无则显示提示 -->
          <el-card shadow="hover" class="detail-card">
            <div v-if="getFilledFields(scope.row).length === 0" class="empty-tip">
              <p>暂无填写的扩展字段</p>
            </div>
            <el-descriptions 
              v-else 
              :column="2" 
              border 
              class="detail-desc"
            >
              <!-- 遍历过滤后的有值字段 -->
              <template v-for="(item, index) in getFilledFields(scope.row)" :key="index">
                <el-descriptions-item 
                  :label="formatKey(item.key)"
                  class="desc-item"
                >
                  {{ formatValue(item.key, item.value) }}
                </el-descriptions-item>
              </template>
            </el-descriptions>
          </el-card>
        </template>
      </el-table-column>

      <!-- 操作列 -->
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="scope">
          <!-- 复制按钮 -->
          <el-button 
            type="primary" 
            size="small" 
            icon="el-icon-copy-document"
            class="copy-btn"
            @click="handleCopyRule(scope.row)"
            style="margin-right: 8px;"
          >
            复制
          </el-button>
          <!-- 删除按钮 -->
          <el-button 
            type="danger" 
            size="small" 
            icon="el-icon-delete"
            class="del-btn"
            @click="delRule(scope.row.id)"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 添加规则弹窗 -->
    <el-dialog 
      title="添加规则" 
      v-model="formVisible" 
      width="60%"
      append-to-body
      draggable
      class="rule-dialog"
      @close="handleDialogClose"
    >
      <!-- 传递copyData属性给RuleForm：新增currentDirection属性传递 -->
      <RuleForm 
        ref="ruleFormRef" 
        @submit="submitAdd" 
        :copyData="currentCopyData" 
        :filterType="currentFilter" 
        :currentDirection="currentDirectionFilter"
      />
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';  // 导入computed
import { ElMessage, ElMessageBox } from 'element-plus';
import { Document } from '@element-plus/icons-vue';
import { getRules, addRule, deleteRule } from '@/api/rule';
import RuleForm from '@/components/RuleForm.vue';

const rules = ref([]);
const formVisible = ref(false);
const loading = ref(false);
const addLoading = ref(false);
// 定义RuleForm的ref实例
const ruleFormRef = ref(null);
// 表格实例
const tableRef = ref(null);
// 存储选中的行数据
const selectedRows = ref([]);
// 存储当前要复制的规则数据
const currentCopyData = ref(null);
// 当前筛选类型（默认“全部”）
const currentFilter = ref('全部');
// 新增：出入站筛选变量（默认“全部”）
const currentDirectionFilter = ref('全部');

onMounted(() => fetchRules());

const fetchRules = () => {
  loading.value = true;
  getRules()
    .then(res => {
      rules.value = res.data || [];
    })
    .catch(err => {
      ElMessage.error(`获取规则失败:${err.message || '服务器异常'}`);
      rules.value = [];
    })
    .finally(() => {
      loading.value = false;
    });
};

// 根据筛选类型过滤规则
const filteredRules = computed(() => {
  // 第一步：先过滤黑白名单
  let filterByList = [];
  switch (currentFilter.value) {
    case '黑名单':
      // 黑名单对应动作：drop（拒绝）
      return rules.value.filter(rule => rule.action === 'drop');
    case '白名单':
      // 白名单对应动作：accept（允许）
      return rules.value.filter(rule => rule.action === 'accept');
    case '全部':
    default:
      filterByList = [...rules.value];
      break;
  }

  // 第二步：再过滤出入站方向
  switch (currentDirectionFilter.value) {
    case '入站':
      return filterByList.filter(rule => rule.direction === 'in');
    case '出站':
      return filterByList.filter(rule => rule.direction === 'out');
    case '全部':
    default:
      return filterByList;
  }
});

const openForm = () => {
  formVisible.value = true;
};

const submitAdd = (data) => {
  addLoading.value = true;
  addRule(data)
    .then(() => {
      ElMessage.success('添加成功');
      formVisible.value = false;
      fetchRules();
    })
    .catch(err => {
      ElMessage.error(`添加规则失败:${err.message || '服务器异常'}`);
    })
    .finally(() => {
      addLoading.value = false;
    });
};

const delRule = (id) => {
  ElMessageBox.confirm(
    // 将单引号改为反引号,使模板字符串生效
    `确定删除该规则ID:${id}吗？删除后不可恢复！`, 
    '删除提示', 
    { 
      type: 'warning',
      confirmButtonText: '确认删除',
      cancelButtonText: '取消'
    }
  )
    .then(() => {
      deleteRule(id)
        .then(() => {
          ElMessage.success('删除成功');
          fetchRules();
        })
        .catch(err => {
          ElMessage.error(`删除规则失败:${err.message || '服务器异常'}`);
        });
    })
    .catch(() => {
      ElMessage.info('已取消删除');
    });
};

// 处理表格选中行变化
const handleSelectionChange = (val) => {
  selectedRows.value = val;
};

// 批量删除规则方法
const batchDelRule = () => {
  // 提取选中的规则ID列表
  const selectedIds = selectedRows.value.map(row => row.id);
  if (selectedIds.length === 0) {
    ElMessage.warning('请选择需要删除的规则');
    return;
  }

  // 确认批量删除
  ElMessageBox.confirm(
    `确定删除选中的【${selectedIds.length}条】规则吗？删除后不可恢复！`,
    '批量删除提示',
    {
      type: 'warning',
      confirmButtonText: '确认删除',
      cancelButtonText: '取消'
    }
  )
    .then(() => {
      const deletePromises = selectedIds.map(id => deleteRule(id));
      Promise.all(deletePromises)
        .then(() => {
          ElMessage.success(`成功删除${selectedIds.length}条规则`);
          fetchRules();
          selectedRows.value = [];
          tableRef.value.clearSelection();
        })
        .catch(err => {
          ElMessage.error(`部分规则删除失败:${err.message || '服务器异常'}`);
          fetchRules();
          selectedRows.value = [];
          tableRef.value.clearSelection();
        });
    })
    .catch(() => {
      ElMessage.info('已取消批量删除');
    });
};

// 处理复制规则的方法
const handleCopyRule = (row) => {
  // 深拷贝规则数据，避免修改原数据
  currentCopyData.value = JSON.parse(JSON.stringify(row));
  // 打开表单弹窗
  formVisible.value = true;
};

// 弹窗关闭时重置表单的方法
const handleDialogClose = () => {
  if (ruleFormRef.value) {
    // 调用RuleForm组件暴露的resetForm方法
    ruleFormRef.value.resetForm();
  }
  // 清空复制数据
  currentCopyData.value = null;
};

// 格式化动作显示
const formatAction = (action) => {
  if (!action) return '未知';
  return action === 'drop' ? '拒绝' : action === 'accept' ? '允许' : `未知(${action})`;
};

// 新增：格式化规则方向显示
const formatDirection = (direction) => {
  if (!direction) return '未知';
  return direction === 'in' ? '入站' : direction === 'out' ? '出站' : `未知(${direction})`;
};

// 格式化字段名
const formatKey = (key) => {
  const keyMap = {
    direction: '规则方向', // 新增：方向字段映射
    id: '规则ID',
    src_ip: '源IP',
    dst_ip: '目标IP',
    src_ip_mask: '源IP掩码',
    dst_ip_mask: '目标IP掩码',
    src_port: '源端口',
    dst_port: '目标端口',
    src_mac: '源MAC',
    dst_mac: '目标MAC',
    proto: 'IP协议',
    time_range: '时间段',
    est: '连接状态',
    content: '内容关键字',
    interface: '网络接口',
    list_type: '名单类型',
    action: '动作'
  };
  // 如果没有映射,就把下划线转空格,首字母大写
  return keyMap[key] || key.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase());
};

// IP协议号与协议名称的映射表
const protoMap = {
  1: 'ICMP (互联网控制消息协议)',
  6: 'TCP (传输控制协议)',
  17: 'UDP (用户数据报协议)',
};

// 格式化字段值
const formatValue = (key, value) => {
  if (key === 'direction') {
    return formatDirection(value);
  }
  // 处理IP协议号/名称
  if (key === 'proto') {
    if (!value) return '未设置';
    // 直接转换为数字/字符串匹配
    const numValue = Number(value);
    if (!isNaN(numValue)) {
      return protoMap[numValue] || `未知协议(${numValue})`;
    }
    // 字符串协议名转大写
    return value.toUpperCase();
  }
  // 连接状态:1→是,0→否
  if (key === 'est') {
    return value === 1 ? '是（只允许已建立连接的数据包）' : '否（允许所有数据包）';
  }
  // 名单类型格式化
  if (key === 'list_type') {
    return value === 'black' ? '黑名单' : '白名单';
  }
  // 内容关键字：兼容数组/字符串，兜底处理竖线
  if (key === 'content') {
    if (!value) return '未设置';
    // 数组→顿号
    if (Array.isArray(value)) {
      return value.join('、');
    }
    // 字符串→替换可能的竖线为顿号，再返回
    return value.replace(/\|/g, '').replace(/\s+/g, '、').trim();
  }
  // 时间段格式化
  if (key === 'time_range') {
    return value ? value.replace(' ', ' - ') : '未设置';
  }
  // MAC地址转大写
  if (key === 'src_mac' || key === 'dst_mac') {
    return value ? value.toUpperCase() : '未设置';
  }
  // 普通值:直接显示
  return value || '未设置';
};

// 过滤出用户填写了的字段
const getFilledFields = (row) => {
  return Object.entries(row).map(([key, value]) => ({ key, value })).filter(item => {
    // 排除已在表格列显示的字段
    if (item.key === 'id' || item.key === 'action') {
      return false;
    }
    if (item.value === '' || item.value === null || item.value === undefined) {
      return false;
    }
    if (Array.isArray(item.value) && item.value.length === 0) {
      return false;
    }
    return true;
  });
};

// 表格行样式
const tableRowClassName = ({ row, rowIndex }) => {
  return 'rule-table-row';
};
</script>

<style scoped>
.rule-manage-container {
  padding: 20px;
  min-height: 600px;
  min-width: 1200px;
  box-sizing: border-box;
}

.top-actions {
  margin-bottom: 16px; 
  display: flex;
  gap: 12px;
  align-items: center;
}

.add-btn {
  border-radius: 6px;
  padding: 8px 16px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.batch-del-btn {
  border-radius: 6px;
  padding: 8px 16px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.filter-group {
  margin-left: 20px;
  display: inline-flex;
  align-items: center;
}

.rule-table {
  width: 100%;
  --el-table-header-text-color: #303133;
  --el-table-row-hover-bg-color: #e6f7ff; 
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

.rule-id {
  display: inline-block;
  padding: 2px 8px;
  background-color: #f0f2f5;
  border-radius: 4px;
  color: #1f2937;
  font-weight: 500;
}

/* 新增：方向标签样式 */
.direction-tag {
  border-radius: 4px;
  padding: 2px 10px;
  font-size: 12px;
}

.action-tag {
  border-radius: 4px;
  padding: 2px 10px;
  font-size: 12px;
}

.detail-card {
  width: 100%;
  border-radius: 6px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

:deep(.detail-card .el-card__body) {
  padding: 16px;
}

.empty-tip {
  text-align: center;
  color: #909399;
  padding: 20px 0;
  font-size: 14px;
}

.detail-desc {
  --el-descriptions-item-label-color: #606266;
  --el-descriptions-item-content-color: #303133;
}

.desc-item {
  padding: 8px 0;
}

.copy-btn {
  border-radius: 4px;
  padding: 6px 12px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.del-btn {
  border-radius: 4px;
  padding: 6px 12px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin: 0 !important;
}

:deep(.rule-dialog .el-dialog__body) {
  padding: 20px;
}

:deep(.rule-table .el-table__header) {
  --el-table-header-text-color: #303133;
  --el-table-header-bg-color: #f8f9fa;
}

:deep(.rule-table .el-table__cell) {
  border-right: 1px solid #ebeef5;
}
</style>
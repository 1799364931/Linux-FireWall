<template>
  <el-form 
    :model="form" 
    label-width="100px" 
    @submit.prevent="onSubmit"
    :rules="rules"
    ref="ruleFormRef"
  >
    <!-- 核心动作设置 -->
    <el-collapse v-model="activeNames" accordion>
      <el-collapse-item title="基础动作设置" name="1">
        <el-form-item label="动作" prop="action">
          <!-- 添加disabled属性，根据filterType控制是否禁用 -->
          <el-radio-group 
            v-model="form.action" 
            :disabled="filterType !== '全部'"
          >
            <el-radio label="drop">丢弃</el-radio>
            <el-radio label="accept">允许</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-collapse-item>

      <!-- IP/端口设置 -->
      <el-collapse-item title="IP/端口设置" name="2">
        <el-form-item label="源IP" prop="src_ip">
          <el-input v-model="form.src_ip" placeholder="如：123.123.123.123"></el-input>
        </el-form-item>
        <el-form-item label="目标IP" prop="dst_ip">
          <el-input v-model="form.dst_ip" placeholder="如：192.168.1.1"></el-input>
        </el-form-item>
        <el-form-item label="源IP掩码" prop="src_ip_mask">
          <el-input v-model="form.src_ip_mask" placeholder="如：192.168.0.0"></el-input>
        </el-form-item>
        <el-form-item label="目标IP掩码" prop="dst_ip_mask">
          <el-input v-model="form.dst_ip_mask" placeholder="如：192.168.0.0"></el-input>
        </el-form-item>
        <el-form-item label="源端口" prop="src_port">
          <el-input v-model.number="form.src_port" placeholder="如：8080" type="number"></el-input>
        </el-form-item>
        <el-form-item label="目标端口" prop="dst_port">
          <el-input v-model.number="form.dst_port" placeholder="如：80" type="number"></el-input>
        </el-form-item>
      </el-collapse-item>

      <!-- MAC/协议设置 -->
      <el-collapse-item title="MAC/协议设置" name="3">
        <el-form-item label="源MAC" prop="src_mac">
          <el-input v-model="form.src_mac" placeholder="如：00:0c:29:09:f2:b0"></el-input>
        </el-form-item>
        <el-form-item label="目标MAC" prop="dst_mac">
          <el-input v-model="form.dst_mac" placeholder="如：00:0c:29:09:f2:b1"></el-input>
        </el-form-item>
        <el-form-item label="IP协议" prop="proto">
          <el-input v-model="form.proto" placeholder="如：icmp/tcp/udp 或数字（6=TCP）"></el-input>
        </el-form-item>
        <el-form-item label="网络接口" prop="interface">
          <el-input v-model="form.interface" placeholder="如：ens12、eth0"></el-input>
        </el-form-item>
      </el-collapse-item>

      <!-- 高级过滤设置 -->
      <el-collapse-item title="高级过滤设置" name="4">
        <el-form-item label="时间段" prop="time_range">
          <el-input v-model="form.time_range" placeholder="如：12:00 14:00（空格分隔开始/结束）"></el-input>
          <div class="form-tip">drop=该时间段丢弃，accept=该时间段允许</div>
        </el-form-item>
        <el-form-item label="连接状态" prop="est">
          <el-select v-model="form.est" placeholder="是否只允许已建立连接的数据包">
            <el-option label="是（1）" :value="1"></el-option>
            <el-option label="否（0）" :value="0"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="内容关键字" prop="content">
          <el-input v-model="form.content" placeholder="如：abcd,efg（多个关键字用空格分隔）"></el-input>
        </el-form-item>
      </el-collapse-item>
    </el-collapse>

    <!-- 提交按钮 -->
    <el-form-item style="margin-top: 20px; text-align: center;">
      <el-button type="primary" @click="onSubmit" :loading="loading">提交</el-button>
      <el-button @click="reset">重置</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup>
import { ref, defineEmits, watch, defineProps } from 'vue';
import { ElMessage } from 'element-plus';

// filterType属性接收父组件的筛选状态
const props = defineProps({
  copyData: {
    type: Object,
    default: () => null
  },
  filterType: {
    type: String,
    default: '全部' 
  }
});

const emit = defineEmits(['submit']);
const loading = ref(false);

// 折叠面板的激活状态（默认只展开基础动作）
const activeNames = ref(['1']);

const ruleFormRef = ref(null);

// 表单数据
const form = ref({
  action: 'drop', // 默认丢弃，必选
  src_ip: '',
  dst_port: '',
  dst_ip: '',
  src_ip_mask: '',
  dst_ip_mask: '',
  src_port: '',
  src_mac: '',
  dst_mac: '',
  proto: '',
  time_range: '',
  est: null,
  content: '',
  interface: ''
});

// 监听filterType变化，自动设置动作值
watch(
  () => props.filterType,
  (newType) => {
    if (newType === '黑名单') {
      form.value.action = 'drop'; // 黑名单强制丢弃
    } else if (newType === '白名单') {
      form.value.action = 'accept'; // 白名单强制允许
    }
    // 全部状态不修改原有值，保持可选择
  },
  { immediate: true } // 立即执行，初始化时就生效
);

// 监听copyData变化，实现数据回显
watch(
  () => props.copyData,
  (newVal) => {
    if (newVal) { // 如果有复制数据
      // 清空表单原有校验提示
      ruleFormRef.value?.clearValidate();
      // 深拷贝数据，避免修改原数据
      const copyData = JSON.parse(JSON.stringify(newVal));
      // 复制数据时，根据filterType强制覆盖动作
      if (props.filterType === '黑名单') {
        copyData.action = 'drop';
      } else if (props.filterType === '白名单') {
        copyData.action = 'accept';
      }
      // 数据类型转换，适配表单绑定
      form.value = {
        action: copyData.action || 'drop',
        src_ip: copyData.src_ip || '',
        dst_ip: copyData.dst_ip || '',
        src_ip_mask: copyData.src_ip_mask || '',
        dst_ip_mask: copyData.dst_ip_mask || '',
        // 数字字段：确保是数字类型（表单用v-model.number绑定）
        src_port: copyData.src_port ? Number(copyData.src_port) : '',
        dst_port: copyData.dst_port ? Number(copyData.dst_port) : '',
        src_mac: copyData.src_mac || '',
        dst_mac: copyData.dst_mac || '',
        proto: copyData.proto || '',
        time_range: copyData.time_range || '',
        // 连接状态：保留数字类型（1/0）
        est: copyData.est === 1 || copyData.est === 0 ? copyData.est : null,
        // 内容关键字：数组转逗号分隔的字符串
        content: Array.isArray(copyData.content) ? copyData.content.join(',') : (copyData.content || ''),
        interface: copyData.interface || ''
      };
      // 优化体验：展开所有折叠面板，方便用户修改
      activeNames.value = ['1', '2', '3', '4'];
      ElMessage.info('已复制规则数据到表单，请修改后提交！');
    }
  },
  { immediate: true, deep: true } // 立即执行 + 深度监听对象变化
);

// 校验规则
const rules = ref({
  action: [{ required: true, message: '请选择动作（丢弃/允许）', trigger: 'change' }],
  src_ip: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else {
          const ipReg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
          ipReg.test(value) ? callback() : callback(new Error('请输入正确的IPv4地址'));
        }
      },
      trigger: 'blur'
    }
  ],
  dst_ip: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else {
          const ipReg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
          ipReg.test(value) ? callback() : callback(new Error('请输入正确的IPv4地址'));
        }
      },
      trigger: 'blur'
    }
  ],
  src_port: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else if (typeof value !== 'number' || value < 1 || value > 65535) {
          callback(new Error('请输入1-65535之间的正整数端口'));
        } else callback();
      },
      trigger: 'blur'
    }
  ],
  dst_port: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else if (typeof value !== 'number' || value < 1 || value > 65535) {
          callback(new Error('请输入1-65535之间的正整数端口'));
        } else callback();
      },
      trigger: 'blur'
    }
  ],
  src_mac: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else {
          const macReg = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
          macReg.test(value) ? callback() : callback(new Error('请输入正确的MAC地址'));
        }
      },
      trigger: 'blur'
    }
  ],
  dst_mac: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else {
          const macReg = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
          macReg.test(value) ? callback() : callback(new Error('请输入正确的MAC地址'));
        }
      },
      trigger: 'blur'
    }
  ],
  proto: [
    {
      validator: (rule, value, callback) => {
        if (!value) {
          callback(); // 可选字段，不填则通过
        } else {
          // 处理输入：去除首尾空格，转为小写
          const inputValue = value.trim().toLowerCase();
          // 定义合法值：协议名（icmp/tcp/udp）+ 协议号（1/6/17）
          const validProtos = new Set(['icmp', 'tcp', 'udp', '1', '6', '17']);
          // 校验：判断是否在合法值中
          if (validProtos.has(inputValue)) {
            callback();
          } else {
            callback(new Error('请输入合法的IP协议（icmp/tcp/udp 或 1/6/17，大小写均可）'));
          }
        }
      },
      trigger: 'blur'
    }
  ],
  // 网络接口（interface）的校验
  interface: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback(); // 可选字段，不填则通过
        else {
          // 合法格式：字母开头，后跟字母/数字（如ens12、eth0），不能有逗号、空格
          const interfaceReg = /^[a-zA-Z][a-zA-Z0-9]*$/;
          if (interfaceReg.test(value.trim())) {
            callback();
          } else {
            callback(new Error('请输入合法的网络接口（如ens12、eth0，不能包含逗号/空格）'));
          }
        }
      },
      trigger: 'blur'
    }
  ],
  time_range: [
    {
      validator: (rule, value, callback) => {
        if (!value) callback();
        else {
          // 支持1位/2位小时（0-23），2位分钟（00-59），空格分隔开始/结束
          const timeReg = /^([0-9]|0[0-9]|1\d|2[0-3]):([0-5]\d) ([0-9]|0[0-9]|1\d|2[0-3]):([0-5]\d)$/;
          if (timeReg.test(value)) {
            // 结束时间不能早于开始时间
            const [startTime, endTime] = value.split(' ');
            const [startH, startM] = startTime.split(':').map(Number);
            const [endH, endM] = endTime.split(':').map(Number);
            const startTotal = startH * 60 + startM;
            const endTotal = endH * 60 + endM;
            if (endTotal < startTotal) {
              callback(new Error('结束时间不能早于开始时间'));
            } else {
              callback();
            }
          } else {
            callback(new Error('请输入正确的时间段（如：9:00 13:00 或 09:00 13:00）'));
          }
        }
      },
      trigger: 'blur'
    }
  ],
  est: [
    {
      validator: (rule, value, callback) => {
        if (value === null) callback();
        else if (value !== 1 && value !== 0) {
          callback(new Error('只能选择是（1）或否（0）'));
        } else callback();
      },
      trigger: 'change'
    }
  ]
});

// 提交方法
const onSubmit = () => {
  if (loading.value) return; // 防止重复点击
  ruleFormRef.value.validate((valid) => {
    if (valid) {
      loading.value = true; // 开启加载
      const formData = { ...form.value };
      // 处理content：逗号转数组
      if (formData.content) {
        formData.content = formData.content.split(',').map(item => item.trim()).filter(item => item);
      } else {
        delete formData.content;
      }
      // 处理数字字段
      ['src_port', 'dst_port', 'est'].forEach(key => {
        if (formData[key] === '' || formData[key] === null) {
          delete formData[key];
        } else {
          formData[key] = Number(formData[key]);
        }
      });
      // 过滤空字段，只保留用户填写的
      const finalData = Object.fromEntries(
        Object.entries(formData).filter(([k, v]) => {
          if (k === 'action') return true;
          return v !== '' && v !== undefined && v !== null;
        })
      );
      emit('submit', finalData);
      setTimeout(() => {
        loading.value = false;
      }, 1000);
      ElMessage.success('表单校验成功，正在提交规则...');
    } else {
      ElMessage.error('表单校验失败，请检查输入格式');
    }
  });
};

// 重置方法
const reset = () => {
  form.value = {
    action: 'drop',
    src_ip: '',
    dst_port: '',
    dst_ip: '',
    src_ip_mask: '',
    dst_ip_mask: '',
    src_port: '',
    src_mac: '',
    dst_mac: '',
    proto: '',
    time_range: '',
    est: null,
    content: '',
    interface: ''
  };
  // 重置时根据filterType重新设置动作
  if (props.filterType === '黑名单') {
    form.value.action = 'drop';
  } else if (props.filterType === '白名单') {
    form.value.action = 'accept';
  }
  ruleFormRef.value?.clearValidate();
  // 重置折叠面板，只展开基础动作
  activeNames.value = ['1'];
};

// 暴露resetForm方法给父组件（名称要和父组件调用的一致）
defineExpose({
  resetForm: reset
});
</script>

<style scoped>
.form-tip {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}
</style>
import service from './index';

// 获取所有规则
export function getRules() {
  return service({ url: '/api/rules', method: 'get' });
}

// 添加规则
export function addRule(data) {
  return service({ url: '/api/rules', method: 'post', data });
}

// 删除规则
export function deleteRule(ruleId) {
  return service({ url: `/api/rules/${ruleId}`, method: 'delete' });
}


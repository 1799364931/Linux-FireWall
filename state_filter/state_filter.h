#ifndef _STATE_FILTER_H
#define _STATE_FILTER_H

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// 连接状态过滤策略（可扩展）
// 函数声明
int init_state_filter(void);                  // 初始化状态过滤模块
void cleanup_state_filter(void);              // 清理状态过滤模块
unsigned int state_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int check_tcp_state(struct sk_buff* skb);

#endif /* _STATE_FILTER_H */
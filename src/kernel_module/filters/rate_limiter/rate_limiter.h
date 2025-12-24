// kernel_module/filters/rate_limiter/rate_limiter.h
#ifndef _RATE_LIMITER_H
#define _RATE_LIMITER_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

/* 限速规则数据结构 */
struct rate_limit_rule {
    struct list_head list;
    
    /* 规则标识 */
    uint32_t rule_id;
    uint32_t priority;
    
    /* 令牌桶参数 */
    uint32_t tokens;              /* 当前令牌数 */
    uint32_t max_tokens;          /* 最大令牌数（桶容量） */
    uint32_t refill_rate;         /* 每秒补充的令牌数（pps） */
    unsigned long last_refill;    /* 上次补充令牌的时间戳 */
    
    /* 匹配条件（0表示不限制） */
    uint32_t src_ip;              /* 源IP */
    uint32_t dst_ip;              /* 目标IP */
    uint16_t src_port;            /* 源端口 */
    uint16_t dst_port;            /* 目标端口 */
    
    /* 统计信息 */
    uint64_t packets_dropped;     /* 累计丢弃包数 */
    uint64_t packets_allowed;     /* 累计允许包数 */
    uint64_t bytes_dropped;       /* 累计丢弃字节数 */
    uint64_t bytes_allowed;       /* 累计允许字节数 */
    unsigned long last_stat_reset;/* 上次重置统计时间 */
    
    /* 并发保护 */
    spinlock_t lock;
    
    /* 启用状态 */
    bool enabled;
};

/* 规则列表结构 */
struct rate_limit_rule_list {
    struct list_head head;
    uint32_t count;
    struct mutex lock;
    uint32_t next_rule_id;
};

/* 全局规则列表 */
extern struct rate_limit_rule_list* g_rate_limit_list;
extern struct mutex rate_limit_list_lock;

/* 获取规则列表 */
struct rate_limit_rule_list* get_rate_limit_list(void);

/* 钩子函数 */
unsigned int rate_limiter_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state);

/* 规则管理接口 */
struct rate_limit_rule* create_rate_limit_rule(uint32_t refill_rate,
                                               uint32_t max_tokens,
                                               uint32_t src_ip,
                                               uint32_t dst_ip,
                                               uint16_t src_port,
                                               uint16_t dst_port,
                                               uint32_t priority);

void destroy_rate_limit_rule(struct rate_limit_rule* rule);

bool add_rate_limit_rule(struct rate_limit_rule* rule);

bool del_rate_limit_rule(uint32_t rule_id);

struct rate_limit_rule* find_rate_limit_rule(uint32_t rule_id);

void reset_rate_limit_stats(uint32_t rule_id);

void enable_rate_limit_rule(uint32_t rule_id, bool enable);

/* 初始化和清理 */
int rate_limiter_init(void);
void rate_limiter_cleanup(void);

#endif /* _RATE_LIMITER_H */
// kernel_module/filters/rate_limiter/rate_limiter_list.h
#ifndef _RATE_LIMITER_LIST_H
#define _RATE_LIMITER_LIST_H

#include <linux/types.h>
#include "rate_limiter.h"

/* 序列化消息结构（用于netlink通信） */
struct rate_limit_entry_msg {
    uint32_t refill_rate;      /* 令牌补充速率（pps） */
    uint32_t max_tokens;       /* 最大令牌数 */
    uint32_t src_ip;           /* 源IP（0表示不限制） */
    uint32_t dst_ip;           /* 目标IP（0表示不限制） */
    uint16_t src_port;         /* 源端口（0表示不限制） */
    uint16_t dst_port;         /* 目标端口（0表示不限制） */
    uint32_t priority;         /* 优先级 */
    uint8_t direction;         /* 0=入站, 1=出站 */
} __attribute__((packed));

/* 规则列表消息（返回给用户态） */
struct rate_limit_rule_msg {
    uint32_t rule_id;
    uint32_t refill_rate;
    uint32_t max_tokens;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t priority;
    uint64_t packets_dropped;
    uint64_t packets_allowed;
    uint64_t bytes_dropped;
    uint64_t bytes_allowed;
    bool enabled;
    uint8_t direction;         /* 0=入站, 1=出站 */
} __attribute__((packed));

/* 构建规则列表消息（用于发送给用户态） */
uint32_t build_rate_limit_list_msg(char** target_buffer_ptr);

/* 清理规则列表消息 */
void cleanup_rate_limit_list_msg(char* buffer);

#endif /* _RATE_LIMITER_LIST_H */
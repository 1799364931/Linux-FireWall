#ifndef _RULE_MATCH_LOGGING_H
#define _RULE_MATCH_LOGGING_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include "../../rule/rule.h"

/**
 * 规则匹配日志记录函数
 * 当规则完全匹配时调用此函数记录相关信息
 * 
 * @param rule_id: 匹配的规则ID
 * @param rule_node: 匹配的规则节点
 * @param skb: 匹配的数据包
 * @param action: 规则的处理动作 ("DROP" 或 "ACCEPT")
 */
void log_rule_match(uint32_t rule_id, 
                    struct rule_list_node* rule_node,
                    struct sk_buff* skb,
                    const char* action);

/**
 * 获取当前系统时间戳
 * 返回格式: "HH:MM:SS.ffffff"
 */
void get_rule_match_timestamp(char* timestamp_buf, size_t buf_size);

#endif /* _RULE_MATCH_LOGGING_H */
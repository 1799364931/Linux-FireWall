/*
 * time_filter.c - 时间过滤器实现
 */
#include "time_filter.h"
#include "../rule/rule.h"              /*拿到时间规则的结构体定义*/
#include "../rule/rule_bitmap.h"       /*拿到规则位图宏定义*/
#include <linux/time.h>                /*内核时间API（ktime_get_real_ts64）*/
#include <linux/rtc.h>                 /*时间转换API（time64_to_tm）*/

/**
 * check_time_in_range - 检查当前时间是否在指定范围内
 */
int check_time_in_range(int start_hour, int start_min, 
                        int end_hour, int end_min)
{
    struct timespec64 ts;
    struct tm tm_now;
    int current_minutes, start_minutes, end_minutes;
    time64_t local_time;
    
    /* 获取当前时间 */
    ktime_get_real_ts64(&ts);
    
    /* 转换为本地时间 (假设UTC+8) */
    local_time = ts.tv_sec + 8 * 3600;
    time64_to_tm(local_time, 0, &tm_now);
    
    /* 将时间转换为分钟数，便于比较 */
    current_minutes = tm_now.tm_hour * 60 + tm_now.tm_min;
    start_minutes = start_hour * 60 + start_min;
    end_minutes = end_hour * 60 + end_min;
    
    /* 处理跨天情况 (如 23:00-01:00) */
    if (start_minutes > end_minutes) {
        /* 跨天规则：在开始时间之后或结束时间之前 */
        return (current_minutes >= start_minutes || 
                current_minutes <= end_minutes);
    } else {
        /* 同天规则：在开始和结束时间之间 */
        return (current_minutes >= start_minutes && 
                current_minutes <= end_minutes);
    }
}

/**
 * time_filter_hook - Netfilter钩子函数
 */
unsigned int time_filter_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct time_rule_list *rule_list;
    struct time_rule *rule;
    
    /* 检查SKB有效性 */
    if (!skb) {
        return NF_ACCEPT;
    }
    
    /* 获取规则列表 */
    rule_list = get_time_rule_list();
    if (!rule_list || list_empty(&rule_list->head)) {
        /* 没有规则，默认接受 */
        return NF_ACCEPT;
    }
    
    /* 遍历所有时间规则 */
    list_for_each_entry(rule, &rule_list->head, list) {
        /* 检查当前时间是否在规则范围内 */
        if (check_time_in_range(rule->start_hour, rule->start_min,
                                rule->end_hour, rule->end_min)) {
            
            /* 更新匹配计数 */
            rule->match_count++;
            
            /* 设置位图标记 */
            SKB_RULE_BITMAP(skb) |= RULE_TIME_FILTER;
            
            /* 根据规则动作决定返回值 */
            if (rule->action == ACTION_DROP) {
                printk(KERN_DEBUG "TimeWall: Packet dropped by time rule "
                       "%02d:%02d-%02d:%02d\n",
                       rule->start_hour, rule->start_min,
                       rule->end_hour, rule->end_min);
                return NF_DROP;
            } else {
                printk(KERN_DEBUG "TimeWall: Packet accepted by time rule "
                       "%02d:%02d-%02d:%02d\n",
                       rule->start_hour, rule->start_min,
                       rule->end_hour, rule->end_min);
                return NF_ACCEPT;
            }
        }
    }
    
    /* 没有匹配的规则，默认接受 */
    return NF_ACCEPT;
}
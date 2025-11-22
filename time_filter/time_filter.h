/*
 * time_filter.h - 时间过滤器头文件
 */
#ifndef _TIME_FILTER_H
#define _TIME_FILTER_H

/* 包含依赖的内核头文件：提供Netfilter和数据包相关的结构体定义 */
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/rtc.h>  /*时间转换API（time64_to_tm）*/
#include "../rule/rule.h"
#include "../rule/rule_bitmap.h"
#include "./time_filter_list/time_filter_list.h" /*拿到时间规则的结构体定义*/

/* Netfilter钩子函数 */
unsigned int time_filter_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state);

/**
 * check_time_in_range - 检查当前时间是否在指定范围内
 * @start_hour: 开始小时
 * @start_min: 开始分钟
 * @end_hour: 结束小时
 * @end_min: 结束分钟
 * 
 * 返回: 1表示在范围内，0表示不在范围内
 */
int check_time_in_range(int start_hour, int start_min, 
                        int end_hour, int end_min);

#endif /* _TIME_FILTER_H */
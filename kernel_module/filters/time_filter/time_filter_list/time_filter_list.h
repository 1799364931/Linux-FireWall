/*
 * rule.h - 时间规则管理
 */
#ifndef _TIME_FILTER_LIST_H
#define _TIME_FILTER_LIST_H

#include <linux/list.h>
#include <linux/time.h>

/* 时间规则结构 */
struct time_rule {
    struct list_head list; /* 链表节点 */

    int start_hour; /* 开始小时 (0-23) */
    int start_min;  /* 开始分钟 (0-59) */
    int end_hour;   /* 结束小时 (0-23) */
    int end_min;    /* 结束分钟 (0-59) */

    unsigned long drop_match_count; /* 匹配次数统计 */
    unsigned long accept_match_count;
};

/* 动作定义 */
#define ACTION_ACCEPT 0
#define ACTION_DROP 1

/* 时间规则链表 */
struct time_rule_list {
    struct list_head head;
    int count;
};

/* 函数声明 */

/**
 * init_time_rules - 初始化时间规则系统
 *
 * 返回: 0表示成功，负数表示失败
 */
int init_time_rules(struct time_rule_list* time_list);

/**
 * cleanup_time_rules - 清理时间规则系统
 */
void cleanup_time_rules(struct time_rule_list* time_list);

/**
 * add_time_rule - 添加时间规则
 * @start_hour: 开始小时
 * @start_min: 开始分钟
 * @end_hour: 结束小时
 * @end_min: 结束分钟
 * @action: 动作 (ACCEPT/DROP)
 *
 * 返回: 0表示成功，负数表示失败
 */
int add_time_rule(int start_hour,
                  int start_min,
                  int end_hour,
                  int end_min,
                  struct time_rule_list* time_list);

/**
 * delete_all_time_rules - 删除所有时间规则
 */
void delete_all_time_rules(struct time_rule_list* time_list);

#endif /* _RULE_H */
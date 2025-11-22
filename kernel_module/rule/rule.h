/*
    防火墙过滤规则
*/
#ifndef _RULE_H
#define _RULE_H

#include <linux/types.h>
#include "../filters/content_filter/content_filter_list/content_filter_list.h"
#include "../filters/time_filter/time_filter_list/time_filter_list.h"

struct match_condition {
    // 这个取值在位图
    uint64_t match_type;
    union {
        __be32 src_ip;
        __be32 dst_ip;
        __be32 src_mask_ip;
        __be32 dst_mask_ip;
        __be16 src_port;
        __be16 dst_port;
        uint8_t* src_mac;
        uint8_t* dst_mac;
        uint8_t ipv4_protocol;
        struct content_rule_list* content_list;
        struct time_rule_list* time_list;
    };
};

struct rule_list_node {
    struct rule_list_node* priv;
    struct rule_list_node* next;
    struct match_condition* rules;
    uint32_t match_condition_size;
    uint64_t rule_bitmap;
};

// 头节点作为哨兵不存储任何信息
struct white_list {
    struct rule_list_node** head;
};

struct black_list {
    struct rule_list_node** head;
};

struct black_list* get_black_list(void);

struct white_list* get_white_list(void);

void add_black_list_rule(struct rule_list_node* new_rule_list_node);

void relase_black_list(void);

uint64_t compute_bitmap(uint32_t size,
                        struct match_condition* match_conditions);


#endif
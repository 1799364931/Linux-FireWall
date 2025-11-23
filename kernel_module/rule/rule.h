/*
    防火墙过滤规则
*/
#ifndef _RULE_H
#define _RULE_H

#include <linux/types.h>
#include <linux/list.h>
#include "../../public_structs/match_condition_msg.h"
#include "../../public_structs/rule_bitmap.h"
#include "../filters/content_filter/content_filter_list/content_filter_list.h"
#include "../filters/time_filter/time_filter_list/time_filter_list.h"


// 不要复用

struct match_condition {
    uint64_t match_type;
    union {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint32_t src_mask_ip;
        uint32_t dst_mask_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t ipv4_protocol;
        uint8_t src_mac[MAC_LENGTH];
        uint8_t dst_mac[MAC_LENGTH];

        char* interface;
        struct content_rule_list* content_list;
        struct time_rule_list* time_list; 
    
    };
};

struct rule_list_node {
    struct list_head list;                
    struct match_condition *conditions; 
    uint32_t condition_count;               
    uint64_t rule_bitmap;      
};

enum rule_list_type {
    RULE_LIST_WHITE,
    RULE_LIST_BLACK,
};

struct rule_list {
    enum rule_list_type type;   // 白名单/黑名单
    struct list_head nodes;     // 链表头
};

static struct rule_list *black_list_singleton = NULL;
static struct rule_list *white_list_singleton = NULL;

struct rule_list *get_rule_list(enum rule_list_type type);

void release_rule_list(struct rule_list *list);

uint64_t compute_bitmap(uint32_t size,
                        struct match_condition_msg *conditions);

#endif /* _RULE_H */

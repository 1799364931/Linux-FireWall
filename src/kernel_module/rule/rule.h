/*
    防火墙过滤规则
*/
#ifndef _RULE_H
#define _RULE_H

#include <linux/list.h>
#include <linux/types.h>

#include "../../public_structs/match_condition_msg.h"
#include "../../public_structs/rule_bitmap.h"
#include "../filters/content_filter/content_filter_list/content_filter_list.h"
#include "../filters/time_filter/time_filter_list/time_filter_list.h"
#define LIST_COUNT 4
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
        // rate_limit_rule_msg
    };
};

struct rule_list_node {
    struct list_head list;
    struct match_condition* conditions;
    uint32_t condition_count;
    uint32_t rule_id;
    uint64_t rule_bitmap;
};

enum rule_list_type {
    RULE_LIST_WHITE,
    RULE_LIST_BLACK,
    RULE_LIST_WHITE_OUTPUT,
    RULE_LIST_BLACK_OUTPUT
};

struct rule_list {
    enum rule_list_type type;  // 白名单/黑名单
    uint32_t rule_count;
    struct list_head nodes;  // 链表头
};

extern struct rule_list* list_singletons[LIST_COUNT];
extern struct mutex list_mutexs[LIST_COUNT];
extern bool BLACK_LIST_ENABLE_INPUT;
extern bool BLACK_LIST_ENABLE_OUTPUT;
extern struct mutex rule_id_lock;

extern uint32_t rule_id;

struct rule_list* get_rule_list(enum rule_list_type type);

void release_rule_list(struct rule_list* list);

uint64_t compute_bitmap(uint32_t size, struct match_condition* conditions);

void release_rule(struct rule_list_node* rule);

bool del_rule(uint32_t del_rule_id, struct rule_list* rule_list);

void init_rule_mutex(void);

void lock_list(enum rule_list_type type);

void unlock_list(enum rule_list_type type);

#endif /* _RULE_H */


#ifndef _IP_RULE_H
#define _IP_RULE_H

#

#include <linux/types.h>



// 黑/白名单IP规则
struct ip_rule{
    uint32_t src_ip;
    // 掩码用于过滤一个网段
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
};

// ip 过滤链
struct ip_while_list_node{
    struct ip_while_list_node* priv;
    struct ip_while_list_node* next;
    struct ip_rule ip_rule;
    uint32_t ip_rule_bitmap;
};

struct ip_black_list_node{
    struct ip_black_list_node* priv;
    struct ip_black_list_node* next;
    struct ip_rule ip_rule;
    uint32_t ip_rule_bitmap;
};






#endif
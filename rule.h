/*
    防火墙过滤规则

    
*/
#ifndef _RULE_H
#define _RULE_H
#include<linux/types.h>

struct match_condition{
    //这个取值在位图
    uint64_t match_type;
    union{
        __be32 src_ip;
        __be32 dst_ip;
        __be32 src_mask_ip;
        __be32 dst_mask_ip;
        __be16 src_port;
        __be16 dst_port;
        uintptr_t src_mac;
        uintptr_t dst_mac;
        uint8_t ipv4_protocol;
    };
};

struct rule_list_node{
    struct rule_list_node* priv;
    struct rule_list_node* next;
    struct match_condition* rules;
    uint32_t match_condition_size;
    uint64_t rule_bitmap;
};

struct white_list{
    struct rule_list_node** head;
};

struct black_list{
    struct rule_list_node** head;
};

struct black_list* get_black_list(){
    static struct black_list black_list;
    return &black_list;
}

struct white_list* get_white_list(){
    static struct white_list white_list;
    return &white_list;
}

uint64_t compute_bitmap(uint32_t size,struct match_condition* match_conditions){
    uint64_t bitmap = 0;
    for(uint32_t i = 0 ;i < size ; i++){
        bitmap |= match_conditions[i].match_type;
    }
    return bitmap;
}

#endif
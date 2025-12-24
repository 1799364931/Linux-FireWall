// kernel_module/filters/rate_limiter/rate_limiter_list.c
#include "rate_limiter_list.h"
#include <linux/slab.h>
#include <linux/string.h>

#define RATE_LIMIT_MSG_SIZE 512

/**
 * 构建限速规则列表消息，用于发送给用户态
 */
uint32_t build_rate_limit_list_msg(char** target_buffer_ptr) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *rule, *n;
    uint32_t total_size;
    uint32_t rule_count;
    char *buffer_ptr;
    struct rate_limit_rule_msg *rule_msg;
    
    list = get_rate_limit_list();
    if (!list) {
        *target_buffer_ptr = kzalloc(sizeof(uint32_t), GFP_KERNEL);
        if (!*target_buffer_ptr)
            return 0;
        *(uint32_t*)(*target_buffer_ptr) = 0;
        return sizeof(uint32_t);
    }
    
    mutex_lock(&list->lock);
    rule_count = list->count;
    
    /* 计算总大小：规则数 + 每个规则的结构体 */
    total_size = sizeof(uint32_t) + 
                 rule_count * sizeof(struct rate_limit_rule_msg);
    
    *target_buffer_ptr = kzalloc(total_size, GFP_KERNEL);
    if (!*target_buffer_ptr) {
        mutex_unlock(&list->lock);
        return 0;
    }
    
    buffer_ptr = *target_buffer_ptr;
    
    /* 写入规则数 */
    *(uint32_t*)buffer_ptr = rule_count;
    buffer_ptr += sizeof(uint32_t);
    
    /* 写入每个规则的信息 */
    list_for_each_entry_safe(rule, n, &list->head, list) {
        rule_msg = (struct rate_limit_rule_msg*)buffer_ptr;
        
        rule_msg->rule_id = rule->rule_id;
        rule_msg->refill_rate = rule->refill_rate;
        rule_msg->max_tokens = rule->max_tokens;
        rule_msg->src_ip = rule->src_ip;
        rule_msg->dst_ip = rule->dst_ip;
        rule_msg->src_port = rule->src_port;
        rule_msg->dst_port = rule->dst_port;
        rule_msg->priority = rule->priority;
        
        spin_lock_bh(&rule->lock);
        rule_msg->packets_dropped = rule->packets_dropped;
        rule_msg->packets_allowed = rule->packets_allowed;
        rule_msg->bytes_dropped = rule->bytes_dropped;
        rule_msg->bytes_allowed = rule->bytes_allowed;
        spin_unlock_bh(&rule->lock);
        
        rule_msg->enabled = rule->enabled;
        
        buffer_ptr += sizeof(struct rate_limit_rule_msg);
    }
    
    mutex_unlock(&list->lock);
    
    return total_size;
}

/**
 * 清理规则列表消息
 */
void cleanup_rate_limit_list_msg(char* buffer) {
    if (buffer)
        kfree(buffer);
}
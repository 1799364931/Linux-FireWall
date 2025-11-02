#include "ip_filter.h"

#define RULE_IP_FILTER RULE_SRC_IP | RULE_SRC_IP_MASK |RULE_DST_IP | RULE_DST_IP_MASK



unsigned int ip_filter_hook(void* priv,
                                struct sk_buff* skb,
                                const struct nf_hook_state* state) {
    struct iphdr* iph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    struct black_list* black_list = get_black_list();

    struct rule_list_node* head = *(black_list->head);
    struct rule_list_node* mov = head->next;

    while (mov != NULL) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_IP_FILTER)) {
            // char buf[30];
            // snprintf(buf, 16, "%pI4", &iph->saddr);
            // printk(KERN_INFO "当前的ip是%s",buf);
            for (uint32_t i = 0; i < mov->match_condition_size ;i ++){
                switch(mov->rules[i].match_type){
                    case RULE_SRC_IP:{
                        if(iph->saddr == mov->rules[i].src_ip){
                            SKB_RULE_BITMAP(skb)|= RULE_SRC_IP;
                            printk(KERN_INFO "yes");
                        }
                        break;
                    }
                    case RULE_SRC_IP_MASK:{
                        if(ip_match_prefix(iph->saddr,mov->rules[i].src_mask_ip)){
                            SKB_RULE_BITMAP(skb)|= RULE_SRC_IP_MASK;
                        }
                        break;
                    }
                    case RULE_DST_IP:{
                        if(iph->daddr == mov->rules[i].dst_ip){
                            SKB_RULE_BITMAP(skb)|= RULE_SRC_IP;
                        }
                        break;
                    }
                    case RULE_DST_IP_MASK:{
                        if(ip_match_prefix(iph->daddr,mov->rules[i].dst_mask_ip)){
                            SKB_RULE_BITMAP(skb)|= RULE_DST_IP_MASK;
                        }
                        break;
                    }
                    default:
                        continue;
                }
            }
        }
        
        if(mov->rule_bitmap == SKB_RULE_BITMAP(skb)){
            return NF_DROP;
        }
        mov = mov->next;
    }
    return NF_ACCEPT;
}

uint8_t calc_prefix_len(uint32_t prefix) {
    uint8_t len = 0;
    while (prefix & 0x80000000) {
        len++;
        prefix <<= 1;
    }
    return len;
}

bool ip_match_prefix(uint32_t ip, uint32_t prefix) {
    uint8_t prefix_len = calc_prefix_len(prefix);
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    return (ip & mask) == (prefix & mask);
}
#include "protocol.h"


#define RULE_PROTOCOL_FILTER RULE_IPV4_PROTOCOL


unsigned int ipv4_protocol_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    
    struct iphdr* iph;


    if (!skb){
        return NF_ACCEPT;
    }
        
    iph = ip_hdr(skb);

    if (!iph){
        return NF_ACCEPT;
    }
    
    struct black_list* black_list = get_black_list();

    struct rule_list_node* head = *(black_list->head);
    struct rule_list_node* mov = head->next;

    while (mov != NULL) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_PROTOCOL_FILTER)) {
            for (uint32_t i = 0; i < mov->match_condition_size ;i ++){
                switch(mov->rules[i].match_type){
                    case RULE_IPV4_PROTOCOL:{
                        if(iph->protocol == mov->rules[i].ipv4_protocol){
                            SKB_RULE_BITMAP(skb)|= RULE_IPV4_PROTOCOL;
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


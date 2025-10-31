
#include "../rule.h"
#include "../rule_bitmap.h"
#include "ip_filter.h"

#define RULE_IP_FILTER RULE_SRC_IP | RULE_SRC_IP_MASK |RULE_DST_IP | RULE_DST_IP_MASK

static struct nf_hook_ops ip_filter_nfho = {
    .hook = ip_filter_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

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
    struct rule_list_node* mov = head;

    while (mov != NULL) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_IP_FILTER)) {
            for (uint32_t i = 0; i < mov->match_condition_size ;i ++){
                switch(mov->rules[i].match_type){
                    case RULE_SRC_IP:{
                        if(iph->saddr == mov->rules[i].src_ip){
                            SKB_RULE_BITMAP(skb)|= RULE_SRC_IP;
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

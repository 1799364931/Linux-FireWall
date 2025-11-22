#include "port_filter.h"


#define RULE_PORT_FILTER RULE_DST_PORT | RULE_SRC_PORT

unsigned int port_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;
    __be16 src_port;
    __be16 dst_port;
    
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    udph = udp_hdr(skb);
    if(!tcph && !udph){
        return NF_ACCEPT;
    }

    if(tcph){
        src_port = tcph->source;
        dst_port = tcph->dest;
    }
    else{
        src_port = udph->source;
        dst_port = udph->dest;
    }

    struct black_list* black_list = get_black_list();

    struct rule_list_node* head = *(black_list->head);
    struct rule_list_node* mov = head->next;

    while (mov != NULL) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_PORT_FILTER)) {
            for (uint32_t i = 0; i < mov->match_condition_size ;i ++){
                switch(mov->rules[i].match_type){
                    case RULE_SRC_PORT:{
                        if(src_port == mov->rules[i].src_port){
                            SKB_RULE_BITMAP(skb)|= RULE_SRC_PORT;
                        }
                        break;
                    }
                    case RULE_DST_PORT:{
                        if(dst_port == mov->rules[i].dst_port){
                            SKB_RULE_BITMAP(skb)|= RULE_DST_PORT;
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


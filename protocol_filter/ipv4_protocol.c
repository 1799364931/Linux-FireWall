#include "protocol.h"

static struct nf_hook_ops ipv4_protocol_filter_nfho = {
    .hook = ipv4_protocol_filter_hook,          // 钩子函数
    .pf = PF_INET,                   // 协议族：IPv4
    .hooknum = NF_INET_PRE_ROUTING,  // 钩子点：在路由之前
    .priority = NF_IP_PRI_FIRST,     // 优先级：最高
};

uint8_t ipv4_protocol = 0;

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
    
    if(iph->protocol == ipv4_protocol){
        return NF_DROP;
    }
    
    return NF_ACCEPT;
}


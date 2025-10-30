#include "mac_filter.h"

static struct nf_hook_ops mac_src_filter_nfho = {
    .hook = mac_src_filter_hook,          // 钩子函数
    .pf = PF_INET,                   // 协议族：IPv4
    .hooknum = NF_INET_PRE_ROUTING,  // 钩子点：在路由之前
    .priority = NF_IP_PRI_FIRST,     // 优先级：最高
};


unsigned char mac[] = {1,2,3,4,5,6};

unsigned int mac_src_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    
    


    struct ethhdr* eth;
    
    if (!skb){
        return NF_ACCEPT;
    }
    
    eth = eth_hdr(skb);
    if (!eth){
        return NF_ACCEPT;
    }
    
    if(memcmp(eth->h_source,mac,ETH_ALEN) == 0){
        return NF_DROP;
    }
    

    return NF_ACCEPT;
}

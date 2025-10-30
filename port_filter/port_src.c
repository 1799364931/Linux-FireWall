#include "port_filter.h"


static struct nf_hook_ops port_src_filter_nfho = {
    .hook = port_src_filter_hook,          // 钩子函数
    .pf = PF_INET,                   // 协议族：IPv4
    .hooknum = NF_INET_PRE_ROUTING,  // 钩子点：在路由之前
    .priority = NF_IP_PRI_FIRST,     // 优先级：最高
};


uint16_t port = 22;

unsigned int port_src_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    if(tcph && port == ntohs(tcph->source)){
        return NF_DROP;
    }

    udph = udp_hdr(skb);
    if(udph && port == ntohs(udph->source)){
        return NF_DROP;
    }
    

    return NF_ACCEPT;
}



#include "ip_filter.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Simple Firewall Module - IP Filter");
MODULE_VERSION("1.0");


static struct nf_hook_ops ip_src_filter_nfho = {
    .hook = ip_src_filter_hook,         
    .pf = PF_INET,                   
    .hooknum = NF_INET_PRE_ROUTING, 
    .priority = NF_IP_PRI_FIRST,    
};


char fip[] = "192.168.119.134";

unsigned int ip_src_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph;
    char ip_str[20];

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    snprintf(ip_str, sizeof(ip_str), "%pI4", &iph->daddr);

    if (strcmp(ip_str, fip) == 0) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

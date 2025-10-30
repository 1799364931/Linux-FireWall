
#include "ip_filter.h"
#include "../rule.h"
#include "../rule_bitmap.h"

static struct nf_hook_ops ip_dst_filter_nfho = {
    .hook = ip_dst_filter_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

unsigned int ip_dst_filter_hook(void* priv,
                                struct sk_buff* skb,
                                const struct nf_hook_state* state) {
    struct iphdr* iph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    

    // 考虑黑名单规则
    

    return NF_ACCEPT;
}

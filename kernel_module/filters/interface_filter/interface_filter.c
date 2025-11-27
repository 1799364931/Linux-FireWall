#include "interface_filter.h"

/* 接口过滤钩子函数 */
unsigned int interface_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct net_device* dev;
    char ifname[MAX_IFNAME_LEN];
    struct iphdr* iph;
    char src_ip[16], dst_ip[16];

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    struct rule_list* balck_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list_node* mov;
    // 黑名单过滤
    dev = state->in;
    if (!dev) {
        return NF_ACCEPT;
    }

    list_for_each_entry(mov, &balck_list->nodes, list) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_INTERFACE)) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                if (mov->rule_bitmap & RULE_INTERFACE) {
                    if (strcmp(dev->name, mov->conditions[i].interface) == 0) {
                        SKB_RULE_BITMAP(skb) |= RULE_INTERFACE;
                    }
                }
            }
        }
        if (mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

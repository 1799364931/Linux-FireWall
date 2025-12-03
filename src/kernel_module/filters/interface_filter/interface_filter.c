#include "interface_filter.h"

/* 接口过滤钩子函数 */
unsigned int interface_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct net_device* dev;
    struct iphdr* iph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    dev = state->in;
    if (!dev) {
        return NF_ACCEPT;
    }

    struct rule_list* rule_list = get_rule_list(
        ENABLE_BLACK_LIST(skb) ? RULE_LIST_BLACK : RULE_LIST_WHITE);
    struct rule_list_node* mov;
    //* 最后流入的hook需要判断白名单是否需要drop
    list_for_each_entry(mov, &rule_list->nodes, list) {
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
        if (ENABLE_BLACK_LIST(skb) &&
            mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_DROP;
        }
        // 白名单不会打上 tag
        // 黑名单会打上 tag
        // SKB_RULE_BITMAP(skb) 白名单/黑名单
        // mov->rule_bitmap 标记了黑名单
        if (!ENABLE_BLACK_LIST(skb) &&
            mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_ACCEPT;
        }
    }

    if (ENABLE_BLACK_LIST(skb)) {
        return NF_ACCEPT;
    } else {
        return NF_DROP;
    }
}

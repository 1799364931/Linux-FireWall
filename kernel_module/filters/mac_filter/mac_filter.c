#include "mac_filter.h"

#define RULE_MAC_FILTER RULE_DST_MAC | RULE_SRC_MAC

unsigned int mac_filter_hook(void* priv,
                             struct sk_buff* skb,
                             const struct nf_hook_state* state) {
    struct ethhdr* eth;

    if (!skb) {
        return NF_ACCEPT;
    }

    eth = eth_hdr(skb);
    if (!eth) {
        return NF_ACCEPT;
    }

    struct rule_list* while_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list_node* mov;
    // 黑名单过滤

    list_for_each_entry(mov, &while_list->nodes, list) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_MAC_FILTER)) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                switch (mov->conditions[i].match_type) {
                    case RULE_SRC_MAC: {
                        if (memcmp(eth->h_source, mov->conditions[i].src_mac,
                                   ETH_ALEN) == 0) {
                            SKB_RULE_BITMAP(skb) |= RULE_SRC_MAC;
                        }
                        break;
                    }
                    case RULE_DST_MAC: {
                        if (memcmp(eth->h_dest, mov->conditions[i].dst_mac,
                                   ETH_ALEN) == 0) {
                            SKB_RULE_BITMAP(skb) |= RULE_DST_MAC;
                        }
                        break;
                    }
                    default:
                        continue;
                }
            }
        }
        if (mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

#include "protocol.h"

#define RULE_PROTOCOL_FILTER RULE_IPV4_PROTOCOL

unsigned int ipv4_protocol_filter_hook(void* priv,
                                       struct sk_buff* skb,
                                       const struct nf_hook_state* state) {
    struct iphdr* iph;

    if (!skb) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    if (!iph) {
        return NF_ACCEPT;
    }
    struct rule_list* balck_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list_node* mov;
    // 黑名单过滤

    list_for_each_entry(mov, &balck_list->nodes, list) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_PROTOCOL_FILTER)) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                switch (mov->conditions[i].match_type) {
                    case RULE_IPV4_PROTOCOL: {
                        if (iph->protocol == mov->conditions[i].ipv4_protocol) {
                            SKB_RULE_BITMAP(skb) |= RULE_IPV4_PROTOCOL;
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

#include "mac_filter.h"
#include "../rule_match_logging/rule_match_logging.h"  // 添加此行

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
    struct rule_list* rule_list = get_rule_list(
        state->hook == NF_INET_LOCAL_IN
            ? (ENABLE_BLACK_LIST(skb) ? RULE_LIST_BLACK : RULE_LIST_WHITE)
            : (ENABLE_BLACK_LIST(skb) ? RULE_LIST_BLACK_OUTPUT
                                      : RULE_LIST_WHITE_OUTPUT));
    struct rule_list_node* mov;
    list_for_each_entry(mov, &rule_list->nodes, list) {
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
  if (ENABLE_BLACK_LIST(skb) &&
            ((mov->rule_bitmap | SKB_RULE_BITMAP(skb)) == SKB_RULE_BITMAP(skb))) {
            log_rule_match(mov->rule_id, mov, skb, "DROP");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}
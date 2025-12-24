#include "port_filter.h"
#include "../rule_match_logging/rule_match_logging.h"  // 添加此行

#define RULE_PORT_FILTER RULE_DST_PORT | RULE_SRC_PORT

unsigned int port_filter_hook(void* priv,
                              struct sk_buff* skb,
                              const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;
    __be16 src_port;
    __be16 dst_port;
    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);
    udph = udp_hdr(skb);
    if (!tcph && !udph) {
        return NF_ACCEPT;
    }
    if (tcph) {
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else {
        src_port = udph->source;
        dst_port = udph->dest;
    }
    struct rule_list* rule_list = get_rule_list(
        ENABLE_BLACK_LIST(skb) ? RULE_LIST_BLACK : RULE_LIST_WHITE);
    struct rule_list_node* mov;
    list_for_each_entry(mov, &rule_list->nodes, list) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_PORT_FILTER)) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                switch (mov->conditions[i].match_type) {
                    case RULE_SRC_PORT: {
                        if (src_port == mov->conditions[i].src_port) {
                            SKB_RULE_BITMAP(skb) |= RULE_SRC_PORT;
                        }
                        break;
                    }
                    case RULE_DST_PORT: {
                        if (dst_port == mov->conditions[i].dst_port) {
                            SKB_RULE_BITMAP(skb) |= RULE_DST_PORT;
                        }
                        break;
                    }
                    default:
                        continue;
                }
            }
        }
        if (ENABLE_BLACK_LIST(skb) && mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            log_rule_match(mov->rule_id, mov, skb, "DROP");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}
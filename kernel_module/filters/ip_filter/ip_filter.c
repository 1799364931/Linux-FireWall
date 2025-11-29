#include "ip_filter.h"
#include <linux/inet.h>

#define RULE_IP_FILTER \
    RULE_SRC_IP | RULE_SRC_IP_MASK | RULE_DST_IP | RULE_DST_IP_MASK

unsigned int ip_filter_hook(void* priv,
                            struct sk_buff* skb,
                            const struct nf_hook_state* state) {


    //this is the first hook?
    memset(skb->cb,0,sizeof(skb->cb));
    struct iphdr* iph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    struct rule_list* balck_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list_node* mov;
    // 黑名单过滤
    list_for_each_entry(mov, &balck_list->nodes, list) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_IP_FILTER)) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                switch (mov->conditions[i].match_type) {
                    case RULE_SRC_IP: {
                        if (iph->saddr == mov->conditions[i].src_ip) {
                            SKB_RULE_BITMAP(skb) |= RULE_SRC_IP;
                            printk(KERN_INFO "yes");
                        }
                        break;
                    }
                    case RULE_SRC_IP_MASK: {
                        if (ip_match_prefix(iph->saddr,
                                            mov->conditions[i].src_mask_ip)) {
                            SKB_RULE_BITMAP(skb) |= RULE_SRC_IP_MASK;
                        }
                        break;
                    }
                    case RULE_DST_IP: {
                        if (iph->daddr == mov->conditions[i].dst_ip) {
                            SKB_RULE_BITMAP(skb) |= RULE_SRC_IP;
                        }
                        break;
                    }
                    case RULE_DST_IP_MASK: {
                        if (ip_match_prefix(iph->daddr,
                                            mov->conditions[i].dst_mask_ip)) {
                            SKB_RULE_BITMAP(skb) |= RULE_DST_IP_MASK;
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

uint8_t calc_prefix_len(uint32_t prefix) {
    uint8_t len = 0;
    while (prefix & 0x80000000) {
        len++;
        prefix <<= 1;
    }
    return len;
}

bool ip_match_prefix(uint32_t ip, uint32_t prefix) {
    uint8_t prefix_len = calc_prefix_len(prefix);
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    return (ip & mask) == (prefix & mask);
}
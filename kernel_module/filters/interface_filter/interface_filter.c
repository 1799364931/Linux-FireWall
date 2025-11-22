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

    struct black_list* black_list = get_black_list();

    struct rule_list_node* head = *(black_list->head);
    struct rule_list_node* mov = head->next;
    dev = state->in;
    if (!dev) {
        return NF_ACCEPT;
    }
    while (mov != NULL) {
        // 判断是否有IP相关的 过滤规则
        if (mov->rule_bitmap & (RULE_INTERFACE)) {
            for (uint32_t i = 0; i < mov->match_condition_size; i++) {
                if (mov->rule_bitmap & RULE_INTERFACE) {
                    if (strcmp(dev->name, mov->rules[i].interface) == 0) {
                        fw_add_log(src_ip, dst_ip, 0, 0, iph->protocol, "DROP",
                                   "Input interface blocked", dev->name);
                        SKB_RULE_BITMAP(skb) |= RULE_INTERFACE;
                    }
                }
            }
        }
        if (mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_DROP;
        }
        mov = mov->next;
    }

    return NF_ACCEPT;
}

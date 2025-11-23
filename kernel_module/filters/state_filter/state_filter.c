#include "state_filter.h"

/**
 * 状态过滤Netfilter钩子函数
 * 逻辑：解析TCP状态 → 只允许已建立连接的数据包通过
 */
unsigned int state_filter_hook(void* priv,
                               struct sk_buff* skb,
                               const struct nf_hook_state* state) {
    // 检查数据包有效性
    if (!skb) {
        return NF_DROP;
    }

    struct black_list* black_list = get_black_list();
    struct rule_list* while_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list_node* mov;
    // 黑名单过滤

    list_for_each_entry(mov, &while_list->nodes, list) {
        if (mov->rule_bitmap & RULE_STATE_POLICY_DENY_ALL_NEW) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                if (mov->conditions[i].match_type ==
                    RULE_STATE_POLICY_DENY_ALL_NEW) {
                    if (!check_tcp_state(skb)) {
                        SKB_RULE_BITMAP(skb) |= RULE_STATE_POLICY_DENY_ALL_NEW;
                    }
                }
            }
        }
        if (mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            return NF_DROP;
        }
    }

    // 检查连接状态，允许则放行，否则丢弃

    // 拒绝所有无效状态的数据包
    return NF_DROP;
}

/**
 * 解析TCP连接状态（核心函数）
 * 返回：1=允许通过（已建立连接），0=拒绝（新连接/无效状态）
 */
static int check_tcp_state(struct sk_buff* skb) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    unsigned int ip_hlen, tcp_hlen;
    // 1. 检查并提取IP头（仅处理IPv4）
    iph = ip_hdr(skb);
    if (iph->version != 4) {
        return 0;  // 非IPv4数据包，拒绝
    }
    ip_hlen = iph->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr)) {
        return 0;  // IP头不完整，拒绝
    }

    // 2. 仅处理TCP协议（UDP/ICMP无连接状态，直接放行或拒绝，可自定义）
    if (iph->protocol != IPPROTO_TCP) {
        // 可选：UDP/ICMP按需求配置，这里默认放行（可改为return 0拒绝）
        return 1;
    }

    // 3. 提取TCP头并检查有效性
    tcph = tcp_hdr(skb);
    tcp_hlen = tcph->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr)) {
        return 0;  // TCP头不完整，拒绝
    }

    // 4. 判断TCP连接状态（核心逻辑）
    // 允许：已建立连接（ESTABLISHED）→ 无SYN/FIN/RST标志，或双向数据传输
    // 拒绝：新连接请求（SYN=1）、关闭连接（FIN=1）、重置连接（RST=1）
    if (tcph->syn) {
        // SYN=1：新连接请求（如浏览器发起的第一次连接），拒绝
        printk(KERN_DEBUG "StateWall: Reject NEW connection (SYN flag set)\n");
        return 0;
    } else if (tcph->fin || tcph->rst) {
        // FIN/RST=1：关闭/重置连接，放行
        printk(
            KERN_DEBUG
            "StateWall: Reject closing/reset connection (FIN/RST flag set)\n");
        return 1;
    } else {
        // 无SYN/FIN/RST：已建立连接的数据包（如HTTP响应、双向数据），允许
        printk(KERN_DEBUG "StateWall: Allow ESTABLISHED connection packet\n");
        return 1;
    }
}

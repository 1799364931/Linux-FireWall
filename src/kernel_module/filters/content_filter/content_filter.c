#include "content_filter.h"
#include "../rule_match_logging/rule_match_logging.h"  // 添加此行

/**
 * 内容过滤Netfilter钩子函数
 * 逻辑：提取TCP负载 → 匹配目标字符串 → 命中则丢弃
 */
static int match_content(void* payload,
                         unsigned int payload_len,
                         struct content_rule_list* content_list);
static void* get_tcp_payload(struct sk_buff* skb, unsigned int* len);
unsigned int content_filter_hook(void* priv,
                                 struct sk_buff* skb,
                                 const struct nf_hook_state* state) {
    void* payload;
    unsigned int payload_len;
    int ret;  // 用于存储skb_linearize的返回值
    // 检查数据包有效性
    if (!skb) {
        return NF_ACCEPT;
    }
    // 重组TCP分片
    // 如果数据包是分片的，重组为连续缓冲区；如果已连续，此函数无影响
    ret = skb_linearize(skb);
    if (ret != 0) {  // 重组失败（极少数情况），直接放行
        printk(KERN_WARNING "ContentWall: Failed to linearize skb (ret=%d)\n",
               ret);
        return NF_ACCEPT;
    }
    // 1. 提取TCP负载（仅处理TCP数据包，如HTTP、SSH等）
    payload = get_tcp_payload(skb, &payload_len);
    if (!payload) {
        return NF_ACCEPT;  // 非TCP数据包或无负载，放行
    }
    struct rule_list* rule_list = get_rule_list(
        ENABLE_BLACK_LIST(skb) ? RULE_LIST_BLACK : RULE_LIST_WHITE);
    struct rule_list_node* mov;
    list_for_each_entry(mov, &rule_list->nodes, list) {
        if (mov->rule_bitmap & RULE_CONTENT) {
            for (uint32_t i = 0; i < mov->condition_count; i++) {
                if (mov->conditions[i].match_type == RULE_CONTENT) {
                    // 遍历
                    if (match_content(payload, payload_len,
                                      mov->conditions[i].content_list)) {
                        SKB_RULE_BITMAP(skb) |= RULE_CONTENT;
                    }
                }
            }
        }
        if (ENABLE_BLACK_LIST(skb) &&
            mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
            log_rule_match(mov->rule_id, mov, skb, "DROP");
            return NF_DROP;
        }
    }
    // 未命中规则，放行
    return NF_ACCEPT;
}
/**
 * 解析数据包：提取TCP负载（IPv4+TCP）
 * 返回：负载起始地址，负载长度存入 len 指针
 */
static void* get_tcp_payload(struct sk_buff* skb, unsigned int* len) {
    struct iphdr* iph;      // IP头指针
    struct tcphdr* tcph;    // TCP头指针
    unsigned int ip_hlen;   // IP头长度
    unsigned int tcp_hlen;  // TCP头长度
    void* payload = NULL;   // 负载起始地址
    *len = 0;
    // 1. 检查并提取IP头（仅处理IPv4）
    iph = ip_hdr(skb);
    if (iph->version != 4) {  // 不是IPv4数据包，直接返回
        return NULL;
    }
    ip_hlen = iph->ihl * 4;                // IP头长度（ihl单位是4字节，需×4）
    if (ip_hlen < sizeof(struct iphdr)) {  // IP头不完整
        return NULL;
    }
    // 2. 检查并提取TCP头（仅处理TCP协议，UDP可类似扩展）
    if (iph->protocol != IPPROTO_TCP) {  // 不是TCP数据包（如ICMP、UDP）
        return NULL;
    }
    tcph = tcp_hdr(skb);
    tcp_hlen = tcph->doff * 4;  // TCP头长度（doff单位是4字节，需×4）
    if (tcp_hlen < sizeof(struct tcphdr)) {  // TCP头不完整
        return NULL;
    }
    // 3. 计算负载起始地址和长度
    payload = (void*)((unsigned char*)iph + ip_hlen + tcp_hlen);
    *len = skb->len - ip_hlen -
           tcp_hlen;  // 总长度 - IP头长度 - TCP头长度 = 负载长度
    // 负载长度必须>0，且不超过数据包实际长度
    if (*len <= 0 || *len > skb->len) {
        return NULL;
    }
    return payload;
}
/**
 * 匹配负载中的目标字符串（支持多条规则）
 * 返回：1=命中规则，0=未命中
 */
static int match_content(void* payload,
                         unsigned int payload_len,
                         struct content_rule_list* content_list) {
    struct content_rule* rule;
    // 遍历所有内容规则
    list_for_each_entry(rule, &content_list->head, list) {
        // 负载长度必须≥目标字符串长度才可能匹配
        if (payload_len < rule->str_len) {
            continue;
        }
        // 字符串匹配
        // strnstr：在 payload 中查找 rule->target_str，最多查找
        // payload_len个字节
        if (strnstr((char*)payload, rule->target_str, payload_len)) {
            // printk(KERN_DEBUG "ContentWall: Matched target string: %s\n",
            //        rule->target_str);
            return 1;  // 命中任意一条规则即返回
        }
    }
    return 0;
}
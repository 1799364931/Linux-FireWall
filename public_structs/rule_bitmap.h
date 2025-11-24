#ifndef _RULE_BITMAP_H
#define _RULE_BITMAP_H

#define RULE_SRC_IP (1 << 0)
#define RULE_SRC_IP_MASK (1 << 1)
#define RULE_DST_IP (1 << 2)
#define RULE_DST_IP_MASK (1 << 3)
#define RULE_SRC_PORT (1 << 4)
#define RULE_DST_PORT (1 << 5)
#define RULE_SRC_MAC (1 << 6)
#define RULE_DST_MAC (1 << 7)
#define RULE_IPV4_PROTOCOL (1 << 8)
#define RULE_CONTENT (1 << 9)
#define RULE_TIME_DROP (1 << 10)
#define RULE_TIME_ACCEPT (1 << 11)
#define RULE_STATE_POLICY_DENY_ALL_NEW (1 << 12)
#define RULE_INTERFACE (1 << 13)

#define SKB_RULE_BITMAP(skb) (*(uint64_t*)(skb->cb))

#endif
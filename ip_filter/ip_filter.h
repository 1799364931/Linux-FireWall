#ifndef _IP_FILTER_H
#define _IP_FILTER_H

#include "../rule.h"
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

extern struct nf_hook_ops ip_dst_filter_nfho;
extern struct nf_hook_ops ip_src_filter_nfho;


unsigned int ip_dst_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

unsigned int ip_src_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);


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

#endif
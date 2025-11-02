#ifndef _IP_FILTER_H
#define _IP_FILTER_H

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "../rule/rule.h"
#include "../rule/rule_bitmap.h"

// extern struct nf_hook_ops ip_filter_nfho;

unsigned int ip_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);


uint8_t calc_prefix_len(uint32_t prefix);

bool ip_match_prefix(uint32_t ip, uint32_t prefix);

#endif
#ifndef _PROTOCOL_FILTER_H
#define _PROTOCOL_FILTER_H

#include "../rule/rule.h"
#include "../rule/rule_bitmap.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>

//extern struct nf_hook_ops ipv4_protocol_filter_nfho;

unsigned int ipv4_protocol_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

#endif
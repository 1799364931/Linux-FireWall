#ifndef _MAC_FILTER_H
#define _MAC_FILTER_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>

extern struct nf_hook_ops mac_dst_filter_nfho;

extern struct nf_hook_ops mac_src_filter_nfho;

unsigned int mac_dst_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

unsigned int mac_src_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

#endif
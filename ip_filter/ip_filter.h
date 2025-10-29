#ifndef _IP_FILTER_H
#define _IP_FILTER_H

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


#endif
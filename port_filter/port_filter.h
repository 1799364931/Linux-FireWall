#ifndef _PORT_FILTER_H
#define _PORT_FILTER_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>

extern struct nf_hook_ops port_filter_nfho;

unsigned int port_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);


#endif
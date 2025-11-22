#ifndef __INTERFACE_FILTER_H__
#define __INTERFACE_FILTER_H__

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/types.h>
#include "../../rule/rule.h"
#include "../../rule/rule_bitmap.h"

#define MAX_IFNAME_LEN 16

unsigned int interface_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);
#endif /* __INTERFACE_FILTER_H__ */
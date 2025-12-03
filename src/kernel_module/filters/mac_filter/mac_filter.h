#ifndef _MAC_FILTER_H
#define _MAC_FILTER_H
#include "../../rule/rule.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include "../../../public_structs/rule_bitmap.h"

unsigned int mac_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

#endif
#ifndef _STATE_FILTER_H
#define _STATE_FILTER_H

#include <linux/netfilter.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "../../rule/rule.h"
#include "../../../public_structs/rule_bitmap.h"


unsigned int state_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif /* _STATE_FILTER_H */
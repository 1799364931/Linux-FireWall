#ifndef _CONTENT_FILTER_H
#define _CONTENT_FILTER_H

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>       // 解析IP头
#include <linux/tcp.h>      // 解析TCP头（UDP同理，可扩展）
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "content_filter_list/content_filter_list.h"
#include "../rule/rule.h"
#include "../rule/rule_bitmap.h"

unsigned int content_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif /* _CONTENT_FILTER_H */
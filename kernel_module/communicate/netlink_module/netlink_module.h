#ifndef _NETLINK_MODULE_H
#define _NETLINK_MODULE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <net/genetlink.h>
#include "../buffer_parse/buffer_parse.h"

int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info);
/// ---------- 定义命令号和属性号 ----------
enum {
    CMD_UNSPEC,
    CMD_ADD_RULE,  // 用户态要调用的命令
    CMD_CHANGE_MOD,
};

enum {
    ATTR_UNSPEC,
    ATTR_BUF,  // 用户态传递的缓冲区
    __ATTR_MAX,
};
#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)

/// ---------- 属性解析策略 ----------
extern const struct nla_policy my_policy[__ATTR_MAX + 1];

/// ---------- 命令表 ----------
extern const struct genl_ops my_ops[];

/// ---------- Family 定义 ----------
extern struct genl_family my_family;

#endif
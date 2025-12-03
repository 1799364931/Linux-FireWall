#ifndef _NETLINK_MODULE_H
#define _NETLINK_MODULE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <net/genetlink.h>
#include "../../../public_structs/netlink_cmd_attr.h"
#include "../buffer_parse/buffer_parse.h"


#define REPLY_MSG_SIZE 64


// todo 考虑建立一个统一的回送字符串接口
int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_del_rule_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_list_rule_msg(struct sk_buff* skb, struct genl_info* info);

int send_rule_list_to_user(const char* black_buf,
                           int black_len,
                           const char* white_buf,
                           int white_len,
                           struct genl_info* info);

int send_msg_to_user(const char* msg_buf,
                     int msg_len,
                     struct genl_info* info,
                     int cmd);

extern const struct nla_policy my_policy[__ATTR_MAX + 1];

extern const struct genl_ops my_ops[];

extern struct genl_family my_family;

#endif
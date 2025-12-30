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

#define REPLY_MSG_SIZE 256

/* Rate Limiter 处理函数 */
int handle_recv_add_rate_limit_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_del_rate_limit_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_list_rate_limit_msg(struct sk_buff* skb,
                                    struct genl_info* info);
int handle_recv_reset_rate_limit_stats_msg(struct sk_buff* skb,
                                           struct genl_info* info);
int handle_recv_logging_register(struct sk_buff* skb, struct genl_info* info);
int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_del_rule_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info);
int handle_recv_list_rule_msg(struct sk_buff* skb, struct genl_info* info);

int send_rule_list_to_user(const char* black_buf,
                           int black_len,
                           const char* white_buf,
                           int white_len,
                           const char* black_buf_out,
                           int black_out_len,
                           const char* white_buf_out,
                           int white_out_len,
                           struct genl_info* info);

int reply_msg_to_user(const char* msg_buf,
                      int msg_len,
                      struct genl_info* info,
                      int cmd,
                      int attr);

int notify_user_event(const char* msg_buf,
                      int msg_len,
                      u32 portid,
                      int cmd,
                      int attr);

extern const struct nla_policy my_policy[__ATTR_MAX + 1];

extern const struct genl_ops my_ops[];

extern struct genl_family my_family;

extern uint32_t user_portid;

#endif
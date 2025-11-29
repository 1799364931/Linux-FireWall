// my_netlink_kernel.c
#include "netlink_module.h"
//todo 这里得写到firewall 模块里面


/// ---------- 命令处理函数 ----------
int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    int len = nla_len(info->attrs[ATTR_BUF]);

    pr_info("netlink: received buffer length=%d\n", len);

    parse_buffer(buf);

    return 0;
}

const struct nla_policy my_policy[__ATTR_MAX + 1] = {
    [ATTR_BUF] = {.type = NLA_BINARY},  // 定义为二进制数据
};

/// ---------- 命令表 ----------
const struct genl_ops my_ops[] = {
    {
        .cmd = CMD_ADD_RULE,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_add_rule_msg,  // 收到命令时调用
    },
};

struct genl_family my_family = {
    .name = "myfirewall",  // 用户态要用的 family 名称
    .version = 1,
    .maxattr = __ATTR_MAX,
    .module = THIS_MODULE,

    .ops = my_ops,
    .n_ops = ARRAY_SIZE(my_ops),
};
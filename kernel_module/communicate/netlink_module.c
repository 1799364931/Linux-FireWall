// my_netlink_kernel.c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <net/genetlink.h>
#include "buffer_parse.h"

//todo 这里得写到firewall 模块里面

/// ---------- 定义命令号和属性号 ----------
enum {
    CMD_UNSPEC,
    CMD_ADD_RULE,  // 用户态要调用的命令
};

enum {
    ATTR_UNSPEC,
    ATTR_BUF,  // 用户态传递的缓冲区
    __ATTR_MAX,
};
#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)

/// ---------- 属性解析策略 ----------
static const struct nla_policy my_policy[__ATTR_MAX + 1] = {
    [ATTR_BUF] = {.type = NLA_BINARY},  // 定义为二进制数据
};

/// ---------- Family 定义 ----------
static struct genl_family my_family = {
    .name = "myfirewall",  // 用户态要用的 family 名称
    .version = 1,
    .maxattr = __ATTR_MAX,
    .module = THIS_MODULE,
};

/// ---------- 命令处理函数 ----------
static int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info) {
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

/// ---------- 命令表 ----------
static const struct genl_ops my_ops[] = {
    {
        .cmd = CMD_ADD_RULE,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_add_rule_msg,  // 收到命令时调用
    },
};

/// ---------- 模块初始化和卸载 ----------
static int __init my_init(void) {
    int ret = genl_register_family(&my_family);
    if (ret) {
        pr_err("netlink: register family failed %d\n", ret);
        return ret;
    }

    ret = genl_register_ops(&my_family, &my_ops[0]);
    if (ret) {
        pr_err("netlink: register ops failed %d\n", ret);
        genl_unregister_family(&my_family);
        return ret;
    }

    pr_info("netlink: kernel module loaded\n");
    return 0;
}

static void __exit my_exit(void) {
    genl_unregister_family(&my_family);
    pr_info("netlink: kernel module unloaded\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");

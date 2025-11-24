// my_netlink_kernel.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/slab.h>

/// ---------- 定义命令号和属性号 ----------
enum {
    MY_CMD_UNSPEC,
    MY_CMD_SEND_BUF,   // 用户态要调用的命令
};

enum {
    MY_ATTR_UNSPEC,
    MY_ATTR_BUF,       // 用户态传递的缓冲区
    __MY_ATTR_MAX,
};
#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)

/// ---------- 属性解析策略 ----------
static const struct nla_policy my_policy[MY_ATTR_MAX + 1] = {
    [MY_ATTR_BUF] = { .type = NLA_BINARY }, // 定义为二进制数据
};

/// ---------- Family 定义 ----------
static struct genl_family my_family = {
    .name = "my_time_family",   // 用户态要用的 family 名称
    .version = 1,
    .maxattr = MY_ATTR_MAX,
    .module = THIS_MODULE,
};

/// ---------- 命令处理函数 ----------
static int handle_send_buf(struct sk_buff *skb, struct genl_info *info)
{
    if (!info->attrs[MY_ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void *buf = nla_data(info->attrs[MY_ATTR_BUF]);
    int len = nla_len(info->attrs[MY_ATTR_BUF]);

    pr_info("netlink: received buffer length=%d\n", len);

    // 假设缓冲区是 uint32_t 数组
    if (len % sizeof(u32) != 0) {
        pr_warn("netlink: buffer not aligned to u32\n");
        return -EINVAL;
    }

    const u32 *p = buf;
    int count = len / sizeof(u32);

    for (int i = 0; i < count; i++) {
        pr_info("netlink: buf[%d] = %u\n", i, p[i]);
    }

    return 0;
}

/// ---------- 命令表 ----------
static const struct genl_ops my_ops[] = {
    {
        .cmd = MY_CMD_SEND_BUF,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_send_buf, // 收到命令时调用
    },
};

/// ---------- 模块初始化和卸载 ----------
static int __init my_init(void)
{
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

static void __exit my_exit(void)
{
    genl_unregister_family(&my_family);
    pr_info("netlink: kernel module unloaded\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");

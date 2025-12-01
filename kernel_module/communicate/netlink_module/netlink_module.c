// my_netlink_kernel.c
#include "netlink_module.h"
// todo 这里得写到firewall 模块里面

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

int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    int len = nla_len(info->attrs[ATTR_BUF]);

    pr_info("netlink: received buffer length=%d\n", len);

    char mode = *((char*)buf);

    if (mode == 'w' || mode == 'W') {
        printk(KERN_INFO "change to while list mode");
        BLACK_LIST_ENABLE = false;
    } else if (mode == 'b' || mode == 'B') {
        printk(KERN_INFO "change to black list mode");
        BLACK_LIST_ENABLE = true;
    }

    return 0;
}


int handle_recv_list_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    int len = nla_len(info->attrs[ATTR_BUF]);

    pr_info("netlink: received buffer length=%d\n", len);

    // 回调
    // 序列化

    // 传递

    return 0;
}

int send_notify_to_user(const char* msg, int len, struct genl_info* info) {
    struct sk_buff* skb;
    void* hdr;

    // 分配一个 netlink 消息
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    // 填充 generic netlink header
    hdr = genlmsg_put(skb, 0, 0, &my_family, 0, CMD_LIST_RULE);
    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    // 添加 payload
    if (nla_put(skb, ATTR_BUF, len, msg)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    // 单播给请求的进程（info->snd_portid）
    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
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
    {
        .cmd = CMD_CHANGE_MOD,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_mode_change_msg,
    }};

struct genl_family my_family = {
    .name = "myfirewall",  // 用户态要用的 family 名称
    .version = 1,
    .maxattr = __ATTR_MAX,
    .module = THIS_MODULE,

    .ops = my_ops,
    .n_ops = ARRAY_SIZE(my_ops),
};
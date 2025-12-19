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
    parse_buffer(buf);

    char* reply_msg = kmalloc(REPLY_MSG_SIZE, GFP_KERNEL);
    sprintf(reply_msg, "add rule success");

    send_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_ADD_RULE_REPLY);

    kfree(reply_msg);
    return 0;
}

int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);

    char mode = *((char*)buf);

    char* reply_msg = kmalloc(REPLY_MSG_SIZE, GFP_KERNEL);

    if (mode == 'w' || mode == 'W') {
        BLACK_LIST_ENABLE = false;
        sprintf(reply_msg, "change to while list mode success");
    } else if (mode == 'b' || mode == 'B') {
        printk(KERN_INFO "change to black list mode");
        sprintf(reply_msg, "change to while list mode success");
    } else {
        sprintf(reply_msg, "change to while list mode fail,unexcept arg");
    }

    send_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_CHANGE_MOD_REPLY);

    kfree(reply_msg);
    return 0;
}

int handle_recv_del_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    del_parse_buffer(buf);

    char* reply_msg = kmalloc(REPLY_MSG_SIZE, GFP_KERNEL);

    sprintf(reply_msg, "del rule success");

    send_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_DEL_RULE_REPLY);

    kfree(reply_msg);
    return 0;
}

int handle_recv_list_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    // 回调
    char *msg_buffer_black, *msg_buffer_white;
    int black_len = build_rule_list_msg(&msg_buffer_black, RULE_LIST_BLACK);
    int white_len = build_rule_list_msg(&msg_buffer_white, RULE_LIST_WHITE);
    send_rule_list_to_user(msg_buffer_black, black_len, msg_buffer_white,
                           white_len, info);

    kfree(msg_buffer_black);
    kfree(msg_buffer_white);

    return 0;
}

int send_rule_list_to_user(const char* black_buf,
                           int black_len,
                           const char* white_buf,
                           int white_len,
                           struct genl_info* info) {
    struct sk_buff* skb;
    void* hdr;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq, &my_family, 0,
                      CMD_LIST_RULE_REPLY);
    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    // 放黑名单属性
    if (nla_put(skb, ATTR_BLACK_LIST, black_len, black_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    // 放白名单属性
    if (nla_put(skb, ATTR_WHITE_LIST, white_len, white_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}

int send_msg_to_user(const char* msg_buf,
                      int msg_len,
                      struct genl_info* info,
                      int cmd) {
    struct sk_buff* skb;
    void* hdr;
    
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq, &my_family, 0, cmd);

    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    if (nla_put(skb, ATTR_BUF, msg_len, msg_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}

const struct nla_policy my_policy[__ATTR_MAX + 1] = {
    [ATTR_BUF] = {.type = NLA_BINARY},  // 定义为二进制数据
    [ATTR_BLACK_LIST] = {.type = NLA_BINARY},
    [ATTR_WHITE_LIST] = {.type = NLA_BINARY}};

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
    },
    {
        .cmd = CMD_LIST_RULE,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_list_rule_msg,
    },
    {
        .cmd = CMD_DEL_RULE,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_del_rule_msg,
    }};

struct genl_family my_family = {
    .name = "myfirewall",  // 用户态要用的 family 名称
    .version = 1,
    .maxattr = __ATTR_MAX,
    .module = THIS_MODULE,

    .ops = my_ops,
    .n_ops = ARRAY_SIZE(my_ops),
};
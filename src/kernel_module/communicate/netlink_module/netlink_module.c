// my_netlink_kernel.c
#include "netlink_module.h"

#include "../../filters/rate_limiter/rate_limiter.h"
#include "../../filters/rate_limiter/rate_limiter_list.h"

// todo 这里得写到firewall 模块里面

#define RATE_REPLY_MSG_SIZE 128

// ============ Rate Limit Handler 处理函数 ============

/**
 * 处理添加限速规则的消息
 */
int handle_recv_add_rate_limit_msg(struct sk_buff* skb,
                                   struct genl_info* info) {
    struct rate_limit_entry_msg* entry;
    struct rate_limit_rule* rule;
    char* reply_msg;

    if (!info->attrs[ATTR_BUF]) {
        printk(KERN_ERR "netlink: missing buffer attribute\n");
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    entry = (struct rate_limit_entry_msg*)nla_data(info->attrs[ATTR_BUF]);

    printk(KERN_INFO "rate_limiter: received add rule request\n");
    printk(KERN_INFO "  rate=%u pps, max_tokens=%u\n", entry->refill_rate,
           entry->max_tokens);
    printk(KERN_INFO "  src_ip=0x%x, dst_ip=0x%x\n", entry->src_ip,
           entry->dst_ip);
    printk(KERN_INFO "  src_port=%hu, dst_port=%hu, priority=%u\n",
           ntohs(entry->src_port), ntohs(entry->dst_port), entry->priority);
    printk(KERN_INFO "  direction=%s\n", /* ← 新增日志 */
           entry->direction == 0 ? "INBOUND" : "OUTBOUND");

    /* 创建新的限速规则 - 传入direction参数 */
    rule = create_rate_limit_rule(entry->refill_rate, entry->max_tokens,
                                  entry->src_ip, entry->dst_ip, entry->src_port,
                                  entry->dst_port, entry->priority,
                                  entry->direction); /* ← 新增参数 */
    if (!rule) {
        reply_msg = kmalloc(RATE_REPLY_MSG_SIZE, GFP_KERNEL);
        sprintf(reply_msg, "add rate limit rule failed: memory error");
        reply_msg_to_user(reply_msg, RATE_REPLY_MSG_SIZE, info,
                          CMD_ADD_RATE_LIMIT_REPLY, ATTR_BUF);
        kfree(reply_msg);
        return -ENOMEM;
    }

    /* 添加规则到列表 */
    if (!add_rate_limit_rule(rule)) {
        reply_msg = kmalloc(RATE_REPLY_MSG_SIZE, GFP_KERNEL);
        sprintf(reply_msg, "add rate limit rule failed: already exists");
        reply_msg_to_user(reply_msg, RATE_REPLY_MSG_SIZE, info,
                          CMD_ADD_RATE_LIMIT_REPLY, ATTR_BUF);
        kfree(reply_msg);
        destroy_rate_limit_rule(rule);
        return -EEXIST;
    }

    reply_msg = kmalloc(RATE_REPLY_MSG_SIZE, GFP_KERNEL);
    sprintf(reply_msg, "add rate limit rule success, rule_id=%u",
            rule->rule_id);
    reply_msg_to_user(reply_msg, RATE_REPLY_MSG_SIZE, info,
                      CMD_ADD_RATE_LIMIT_REPLY, ATTR_BUF);
    kfree(reply_msg);
    return 0;
}

/**
 * 处理删除限速规则的消息
 */
int handle_recv_del_rate_limit_msg(struct sk_buff* skb,
                                   struct genl_info* info) {
    uint32_t* rule_id;
    char* reply_msg;
    bool success;

    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    rule_id = (uint32_t*)nla_data(info->attrs[ATTR_BUF]);

    printk(KERN_INFO "rate_limiter: received delete rule request, rule_id=%u\n",
           *rule_id);

    success = del_rate_limit_rule(*rule_id);

    reply_msg = kmalloc(RATE_REPLY_MSG_SIZE, GFP_KERNEL);
    if (success) {
        sprintf(reply_msg, "delete rate limit rule success");
    } else {
        sprintf(reply_msg, "delete rate limit rule failed: rule not found");
    }

    reply_msg_to_user(reply_msg, RATE_REPLY_MSG_SIZE, info,
                      CMD_DEL_RATE_LIMIT_REPLY, ATTR_BUF);
    kfree(reply_msg);

    return success ? 0 : -ENOENT;
}

/**
 * 处理列出限速规则的消息
 */
int handle_recv_list_rate_limit_msg(struct sk_buff* skb,
                                    struct genl_info* info) {
    char* msg_buffer;
    uint32_t msg_len;
    struct sk_buff* reply_skb;
    void* hdr;

    // printk(KERN_INFO "=== handle_recv_list_rate_limit_msg called ===\n");

    msg_len = build_rate_limit_list_msg(&msg_buffer);

    printk(KERN_INFO "Built rate limit list message, length = %u bytes\n",
           msg_len);

    if (!msg_buffer) {
        printk(KERN_ERR "rate_limiter: failed to build rule list message\n");
        pr_err("rate_limiter: failed to build rule list message\n");
        return -ENOMEM;
    }

    /* 发送消息回用户态 */
    reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!reply_skb) {
        printk(KERN_ERR "genlmsg_new failed\n");
        cleanup_rate_limit_list_msg(msg_buffer);
        return -ENOMEM;
    }

    printk(KERN_INFO "genlmsg_new successful\n");

    hdr = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq, &my_family, 0,
                      CMD_LIST_RATE_LIMIT_REPLY);
    if (!hdr) {
        printk(KERN_ERR "genlmsg_put failed\n");
        nlmsg_free(reply_skb);
        cleanup_rate_limit_list_msg(msg_buffer);
        return -ENOMEM;
    }

    printk(KERN_INFO "genlmsg_put successful\n");

    if (nla_put(reply_skb, ATTR_RATE_LIMIT_LIST, msg_len, msg_buffer)) {
        printk(KERN_ERR "nla_put failed, msg_len = %u\n", msg_len);
        nlmsg_free(reply_skb);
        cleanup_rate_limit_list_msg(msg_buffer);
        return -EMSGSIZE;
    }

    printk(KERN_INFO "nla_put successful\n");

    genlmsg_end(reply_skb, hdr);
    cleanup_rate_limit_list_msg(msg_buffer);

    printk(KERN_INFO "Sending reply to user space, portid = %u\n",
           info->snd_portid);
    int result =
        genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid);
    printk(KERN_INFO "genlmsg_unicast returned %d\n", result);

    return result;
}
/**
 * 处理重置统计信息的消息
 */
int handle_recv_reset_rate_limit_stats_msg(struct sk_buff* skb,
                                           struct genl_info* info) {
    uint32_t* rule_id;
    char* reply_msg;
    struct rate_limit_rule* rule;

    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    rule_id = (uint32_t*)nla_data(info->attrs[ATTR_BUF]);

    printk(KERN_INFO "rate_limiter: received reset stats request, rule_id=%u\n",
           *rule_id);

    rule = find_rate_limit_rule(*rule_id);

    reply_msg = kmalloc(RATE_REPLY_MSG_SIZE, GFP_KERNEL);
    if (rule) {
        reset_rate_limit_stats(*rule_id);
        sprintf(reply_msg, "reset rate limit stats success");
    } else {
        sprintf(reply_msg, "reset rate limit stats failed: rule not found");
    }

    reply_msg_to_user(reply_msg, RATE_REPLY_MSG_SIZE, info,
                      CMD_RESET_RATE_LIMIT_STATS_REPLY, ATTR_BUF);
    kfree(reply_msg);

    return rule ? 0 : -ENOENT;
}
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

    reply_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_ADD_RULE_REPLY,
                      ATTR_BUF);

    kfree(reply_msg);
    return 0;
}

int handle_recv_mode_change_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    int len = nla_len(info->attrs[ATTR_BUF]);
    char mode = *((char*)buf);

    char* reply_msg = kmalloc(REPLY_MSG_SIZE, GFP_KERNEL);

    if (mode == 'w' || mode == 'W') {
        if (len > 1) {
            BLACK_LIST_ENABLE_INPUT = false;
            sprintf(reply_msg, "change to while list mode out success");
        } else {
            BLACK_LIST_ENABLE_INPUT = false;
            sprintf(reply_msg, "change to while list mode in success");
        }

    } else if (mode == 'b' || mode == 'B') {
        if (len > 1) {
            BLACK_LIST_ENABLE_INPUT = true;
            sprintf(reply_msg, "change to black list mode out success");
        } else {
            BLACK_LIST_ENABLE_INPUT = true;
            sprintf(reply_msg, "change to black list mode in success");
        }
    } else {
        sprintf(reply_msg, "change to while list mode fail,unexcept arg");
    }

    reply_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_CHANGE_MOD_REPLY,
                      ATTR_BUF);

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

    reply_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_DEL_RULE_REPLY,
                      ATTR_BUF);

    kfree(reply_msg);
    return 0;
}

int handle_recv_list_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    // 回调
    char *msg_buffer_black, *msg_buffer_white, *msg_buffer_black_out,
        *msg_buffer_white_out;

    int black_len = build_rule_list_msg(&msg_buffer_black, RULE_LIST_BLACK);
    int white_len = build_rule_list_msg(&msg_buffer_white, RULE_LIST_WHITE);

    int black_out_len =
        build_rule_list_msg(&msg_buffer_black_out, RULE_LIST_BLACK_OUTPUT);
    int white_out_len =
        build_rule_list_msg(&msg_buffer_white_out, RULE_LIST_WHITE_OUTPUT);

    send_rule_list_to_user(msg_buffer_black, black_len, msg_buffer_white,
                           white_len, msg_buffer_black_out, black_out_len,
                           msg_buffer_white_out, white_out_len, info);

    kfree(msg_buffer_black);
    kfree(msg_buffer_white);
    kfree(msg_buffer_black_out);
    kfree(msg_buffer_white_out);
    return 0;
}

// 注册用户态的portid
int handle_recv_logging_register(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    user_portid = info->snd_portid;

    return 0;
}

int send_rule_list_to_user(const char* black_buf,
                           int black_len,
                           const char* white_buf,
                           int white_len,
                           const char* black_buf_out,
                           int black_out_len,
                           const char* white_buf_out,
                           int white_out_len,
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

    // 放黑名单属性
    if (nla_put(skb, ATTR_BLACK_LIST_OUTPUT, black_out_len, black_buf_out)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    // 放白名单属性
    if (nla_put(skb, ATTR_WHITE_LIST_OUTPUT, white_out_len, white_buf_out)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}

int reply_msg_to_user(const char* msg_buf,
                      int msg_len,
                      struct genl_info* info,
                      int cmd,
                      int attr) {
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

    if (nla_put(skb, attr, msg_len, msg_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}

int notify_user_event(const char* msg_buf,
                      int msg_len,
                      u32 portid,
                      int cmd,
                      int attr) {
    struct sk_buff* skb;
    void* hdr;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, 0, 0, &my_family, 0, cmd);
    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    if (nla_put(skb, attr, msg_len, msg_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, hdr);

    return genlmsg_unicast(&init_net, skb, portid);
}

uint32_t user_portid = 0;  //

const struct nla_policy my_policy[__ATTR_MAX + 1] = {
    [ATTR_BUF] = {.type = NLA_BINARY},  // 定义为二进制数据
    [ATTR_BLACK_LIST] = {.type = NLA_STRING},
    [ATTR_WHITE_LIST] = {.type = NLA_STRING},
    [ATTR_BLACK_LIST_OUTPUT] = {.type = NLA_STRING},
    [ATTR_WHITE_LIST_OUTPUT] = {.type = NLA_STRING},
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
    },
    /* 新增：Rate Limiter 命令处理 */
    {
        .cmd = CMD_ADD_RATE_LIMIT,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_add_rate_limit_msg,
    },
    {
        .cmd = CMD_DEL_RATE_LIMIT,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_del_rate_limit_msg,
    },
    {
        .cmd = CMD_LIST_RATE_LIMIT,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_list_rate_limit_msg,
    },
    {
        .cmd = CMD_RESET_RATE_LIMIT_STATS,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_reset_rate_limit_stats_msg,
    },
    //
    {
        .cmd = CMD_LOGGING_REGISTER,
        .flags = 0,
        .policy = my_policy,
        .doit = handle_recv_logging_register,
    }};

struct genl_family my_family = {
    .name = "myfirewall",  // 用户态要用的 family 名称
    .version = 1,
    .maxattr = __ATTR_MAX,
    .module = THIS_MODULE,

    .ops = my_ops,
    .n_ops = ARRAY_SIZE(my_ops),
};
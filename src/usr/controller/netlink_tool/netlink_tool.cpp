#include "netlink_tool.h"

static int seq_handler(struct nl_msg* msg, void* arg) {
    return NL_OK;
}

bool netlink_tool::init() {
    sock_ = nl_socket_alloc();
    // 绑定到“有效消息”阶段
    nl_socket_modify_cb(sock_, NL_CB_VALID, NL_CB_CUSTOM, recv_msg, nullptr);
    // 关闭seq检查
    nl_socket_modify_cb(sock_, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, seq_handler,
                        nullptr);
    if (!sock_) {
        std::cerr << "nl_socket_alloc failed\n";
        return false;
    }
    if (genl_connect(sock_)) {
        std::cerr << "genl_connect failed\n";
        return false;
    }
    family_id_ = genl_ctrl_resolve(sock_, family_name_.c_str());
    if (family_id_ < 0) {
        std::cerr << "genl_ctrl_resolve failed\n";
        return false;
    }
    return true;
}

bool netlink_tool::send_buffer(const char* startpos,
                               uint32_t bufferlen,
                               int cmd,
                               int attr) {
    if (!sock_ || family_id_ < 0)
        return false;

    struct nl_msg* msg = nlmsg_alloc();
    if (!msg) {
        std::cerr << "nlmsg_alloc failed\n";
        return false;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id_, 0, 0, cmd,
                     1)) {
        std::cerr << "genlmsg_put failed\n";
        nlmsg_free(msg);
        return false;
    }

    if (nla_put(msg, attr, bufferlen, startpos) < 0) {
        std::cerr << "nla_put failed\n";
        nlmsg_free(msg);
        return false;
    }

    int err = nl_send_auto(sock_, msg);
    nlmsg_free(msg);

    if (err < 0) {
        std::cerr << "nl_send_auto failed: " << err << "\n";
        return false;
    }
    return true;
}

int netlink_tool::recv_msg(struct nl_msg* msg, void* arg) {
    struct nlmsghdr* nlh = nlmsg_hdr(msg);
    struct genlmsghdr* gnlh = (genlmsghdr*)nlmsg_data(nlh);
    struct nlattr* attrs[__ATTR_MAX + 1];

    // 解析属性
    genlmsg_parse(nlh, 0, attrs, __ATTR_MAX, nullptr);

    switch (gnlh->cmd) {
        case CMD_LIST_RULE_REPLY: {
            if (attrs[ATTR_BLACK_LIST]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_BLACK_LIST]);
                int len = nla_len(attrs[ATTR_BLACK_LIST]);
                std::cout << "BLACK_LIST_IN:\n"
                          << std::string(buf, len) << std::endl;
            }
            // 白名单属性
            if (attrs[ATTR_WHITE_LIST]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_WHITE_LIST]);
                int len = nla_len(attrs[ATTR_WHITE_LIST]);
                std::cout << "WHITE_LIST_IN:\n"
                          << std::string(buf, len) << std::endl;
            }
            //出站规则
            if (attrs[ATTR_BLACK_LIST_OUTPUT]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_BLACK_LIST_OUTPUT]);
                int len = nla_len(attrs[ATTR_BLACK_LIST_OUTPUT]);
                std::cout << "BLACK_LIST_OUT:\n"
                          << std::string(buf, len) << std::endl;
            }
            // 白名单属性
            if (attrs[ATTR_WHITE_LIST_OUTPUT]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_WHITE_LIST_OUTPUT]);
                int len = nla_len(attrs[ATTR_WHITE_LIST_OUTPUT]);
                std::cout << "WHITE_LIST_OUT:\n"
                          << std::string(buf, len) << std::endl;
            }
            break;
        }
        // ============ Rate Limit 相关回复处理 ============
        case CMD_LIST_RATE_LIMIT_REPLY: {
            if (attrs[ATTR_RATE_LIMIT_LIST]) {
                const char* buf =
                    (const char*)nla_data(attrs[ATTR_RATE_LIMIT_LIST]);
                int len = nla_len(attrs[ATTR_RATE_LIMIT_LIST]);

                // 解析规则列表
                if (len < (int)sizeof(uint32_t)) {
                    std::cout << "Error: invalid rate limit list message"
                              << std::endl;
                    break;
                }

                uint32_t rule_count = *(uint32_t*)buf;
                std::cout << "=== Rate Limit Rules ===\n";
                std::cout << "Total rules: " << rule_count << "\n\n";

                if (rule_count == 0) {
                    std::cout << "No rate limit rules configured." << std::endl;
                    break;
                }

                // 定义规则消息结构体（与内核的 rate_limit_rule_msg 一致）
                struct rate_limit_rule_msg {
                    uint32_t rule_id;
                    uint32_t refill_rate;
                    uint32_t max_tokens;
                    uint32_t src_ip;
                    uint32_t dst_ip;
                    uint16_t src_port;
                    uint16_t dst_port;
                    uint32_t priority;
                    uint64_t packets_dropped;
                    uint64_t packets_allowed;
                    uint64_t bytes_dropped;
                    uint64_t bytes_allowed;
                    bool enabled;
                } __attribute__((packed));

                /*

                struct rate_limit_rule_msg {
                    uint32_t rule_id;
                    uint32_t refill_rate;
                    uint32_t max_tokens;
                    uint32_t priority;
                    uint64_t packets_dropped;
                    uint64_t packets_allowed;
                    uint64_t bytes_dropped;
                    uint64_t bytes_allowed;
                } __attribute__((packed));

                */

                const char* ptr = buf + sizeof(uint32_t);
                for (uint32_t i = 0; i < rule_count; i++) {
                    const struct rate_limit_rule_msg* rule_msg =
                        (const struct rate_limit_rule_msg*)ptr;

                    std::cout << "Rule ID: " << rule_msg->rule_id << "\n";
                    std::cout << "  Rate: " << rule_msg->refill_rate
                              << " pps\n";
                    std::cout << "  Max Tokens: " << rule_msg->max_tokens
                              << "\n";
                    std::cout << "  Priority: " << rule_msg->priority << "\n";

                    if (rule_msg->src_ip != 0) {
                        uint32_t ip = htonl(rule_msg->src_ip);
                        std::cout << "  Src IP: ";
                        printf("%u.%u.%u.%u\n", (ip >> 24) & 0xFF,
                               (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                    }

                    if (rule_msg->dst_ip != 0) {
                        uint32_t ip = htonl(rule_msg->dst_ip);
                        std::cout << "  Dst IP: ";
                        printf("%u.%u.%u.%u\n", (ip >> 24) & 0xFF,
                               (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                    }

                    if (rule_msg->src_port != 0) {
                        std::cout << "  Src Port: " << ntohs(rule_msg->src_port)
                                  << "\n";
                    }

                    if (rule_msg->dst_port != 0) {
                        std::cout << "  Dst Port: " << ntohs(rule_msg->dst_port)
                                  << "\n";
                    }

                    std::cout << "  Status: "
                              << (rule_msg->enabled ? "enabled" : "disabled")
                              << "\n";
                    std::cout
                        << "  Packets Allowed: " << rule_msg->packets_allowed
                        << "\n";
                    std::cout
                        << "  Packets Dropped: " << rule_msg->packets_dropped
                        << "\n";
                    std::cout << "  Bytes Allowed: " << rule_msg->bytes_allowed
                              << "\n";
                    std::cout << "  Bytes Dropped: " << rule_msg->bytes_dropped
                              << "\n";
                    std::cout << "\n";

                    ptr += sizeof(struct rate_limit_rule_msg);
                }
            } else {
                for (int i = 0; i <= __ATTR_MAX; i++) {
                    if (attrs[i]) {
                        std::cout << "  attrs[" << i << "] exists" << std::endl;
                    }
                }
            }
            break;
        }
        // ============ 日志获取 ==========
        case CMD_LOGGING_FETCH: {
            if (attrs[ATTR_LOG]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_LOG]);
                int len = nla_len(attrs[ATTR_LOG]);
                // 不要打印
                // 存到一个信息结构体
                // std::cout << std::string(buf, len) << std::endl;
                log_info_queue_.put_log(std::string(buf, len));
            }
            break;
        }
        // ============ 默认情况处理其他回复 ============
        default: {
            if (attrs[ATTR_BUF]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_BUF]);
                int len = nla_len(attrs[ATTR_BUF]);
                std::cout << std::string(buf, len) << std::endl;
            }
        }
    }
    return NL_OK;
}

bool netlink_tool::recv_reply_once() {
    if (!sock_) {
        return false;
    }

    int err = nl_recvmsgs_default(sock_);
    if (err < 0) {
        std::cerr << "nl_recvmsgs_default failed: " << nl_geterror(err)
                  << std::endl;
        return false;
    }
    return true;
}

log_info_queue netlink_tool::log_info_queue_;

// bool netlink_tool::recv_notify_once() {
//     if (!sock_) {
//         return false;
//     }

//     int err =
//         nl_recvmsgs(sock_, )  // 用自定义 cb，不走 default 的严格 seq 检查 }

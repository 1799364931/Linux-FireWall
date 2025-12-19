#include "netlink_tool.h"

bool netlink_tool::init() {
    sock_ = nl_socket_alloc();
    nl_socket_modify_cb(sock_, NL_CB_VALID, NL_CB_CUSTOM, recv_msg, nullptr);
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
                std::cout << "Kernel notify (BLACK):\n"
                          << std::string(buf, len) << std::endl;
            }

            // 白名单属性
            if (attrs[ATTR_WHITE_LIST]) {
                const char* buf = (const char*)nla_data(attrs[ATTR_WHITE_LIST]);
                int len = nla_len(attrs[ATTR_WHITE_LIST]);
                std::cout << "Kernel notify (WHITE):\n"
                          << std::string(buf, len) << std::endl;
            }
            break;
        }
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

bool netlink_tool::recv_once() {
    if (!sock_)
        return false;
    int err = nl_recvmsgs_default(sock_);
    if (err < 0) {
        std::cerr << "nl_recvmsgs_default failed: " << nl_geterror(err)
                  << std::endl;
        return false;
    }
    return true;
}
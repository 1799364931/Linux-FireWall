#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/msg.h>
#include <netlink/netlink.h>
#include <cstdint>
#include <cstring>
#include <iostream>

class netlink_tool {
   public:
    // 构造函数只需要 family_name
    netlink_tool(const std::string& family_name)
        : family_name_(family_name), sock_(nullptr), family_id_(-1) {}

    ~netlink_tool() {
        if (sock_)
            nl_socket_free(sock_);
    }

    // 初始化 Netlink socket 并解析 family id
    bool init() {
        sock_ = nl_socket_alloc();
        // 绑定到“有效消息”阶段
        nl_socket_modify_cb(sock_, NL_CB_VALID, NL_CB_CUSTOM, recv_rule_list,
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

    // 发送 buffer，cmd 和 attr 作为参数传入
    bool send_buffer(const char* startpos,
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

    static int recv_rule_list(struct nl_msg* msg, void* arg) {
        struct nlmsghdr* nlh = nlmsg_hdr(msg);
        // struct genlmsghdr* gnlh = (genlmsghdr*)nlmsg_data(nlh);
        struct nlattr* attrs[__ATTR_MAX + 1];

        // 解析属性
        genlmsg_parse(nlh, 0, attrs, __ATTR_MAX, nullptr);

        // 黑名单属性
        if (attrs[ATTR_BLACK_LIST]) {
            const char* buf = (const char*)nla_data(attrs[ATTR_BLACK_LIST]);
            int len = nla_len(attrs[ATTR_BLACK_LIST]);
            std::cout << "Kernel notify (BLACK): " << std::string(buf, len)
                      << std::endl;
        }

        // 白名单属性
        if (attrs[ATTR_WHITE_LIST]) {
            const char* buf = (const char*)nla_data(attrs[ATTR_WHITE_LIST]);
            int len = nla_len(attrs[ATTR_WHITE_LIST]);
            std::cout << "Kernel notify (WHITE): " << std::string(buf, len)
                      << std::endl;
        }

        return NL_OK;
    }

    bool recv_once() {
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

   private:
    enum {
        CMD_UNSPEC,
        CMD_ADD_RULE,  // 用户态要调用的命令
        CMD_CHANGE_MOD,
        CMD_LIST_RULE_CTRL,
        CMD_LIST_RULE
    };

    enum {
        ATTR_UNSPEC,
        ATTR_BUF,  // 用户态传递的缓冲区
        ATTR_BLACK_LIST,
        ATTR_WHITE_LIST,
        __ATTR_MAX,
    };

    std::string family_name_;  // Netlink family 名称
    struct nl_sock* sock_;     // Netlink socket
    int family_id_;            // family id（通过名字解析得到）
};

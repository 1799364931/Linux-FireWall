#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <cstdint>
#include <cstring>
#include <iostream>

class netlink_tool {
   public:
    netlink_tool(const std::string& family_name, int cmd, int attr)
        : family_name_(family_name),
          cmd_(cmd),
          attr_(attr),
          sock_(nullptr),
          family_id_(-1) {}

    ~netlink_tool() {
        if (sock_)
            nl_socket_free(sock_);
    }

    bool init() {
        sock_ = nl_socket_alloc();
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

    bool send_buffer(const char* startpos, uint32_t bufferlen) {
        if (!sock_ || family_id_ < 0)
            return false;

        struct nl_msg* msg = nlmsg_alloc();
        if (!msg) {
            std::cerr << "nlmsg_alloc failed\n";
            return false;
        }

        if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id_, 0, 0, cmd_,
                         1)) {
            std::cerr << "genlmsg_put failed\n";
            nlmsg_free(msg);
            return false;
        }

        if (nla_put(msg, attr_, bufferlen, startpos) < 0) {
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

   private:
    std::string family_name_;
    int cmd_;
    int attr_;
    struct nl_sock* sock_;
    int family_id_;
};

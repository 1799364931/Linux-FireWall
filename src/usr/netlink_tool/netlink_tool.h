#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/msg.h>
#include <netlink/netlink.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "../../public_structs/netlink_cmd_attr.h"

class netlink_tool {
   public:
    // 构造函数只需要 family_name
    netlink_tool(const std::string& family_name)
        : family_name_(family_name), sock_(nullptr), family_id_(-1) {}

    ~netlink_tool() {
        if (sock_) {
            nl_socket_free(sock_);
        }
    }

    // 初始化 Netlink socket 并解析 family id
    bool init();

    // 发送 buffer，cmd 和 attr 作为参数传入
    bool send_buffer(const char* startpos,
                     uint32_t bufferlen,
                     int cmd,
                     int attr);

    static int recv_msg(struct nl_msg* msg, void* arg);

    bool recv_once();

   private:
    std::string family_name_;  // Netlink family 名称
    struct nl_sock* sock_;     // Netlink socket
    int family_id_;            // family id（通过名字解析得到）
};

// usr/netlink_tool/netlink_tool.h
#ifndef _NETLINK_TOOL_H
#define _NETLINK_TOOL_H

#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/msg.h>
#include <netlink/netlink.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <queue>
#include <string>
#include "../../../public_structs/netlink_cmd_attr.h"
#include "log_info_queue.h"

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

    // 接收消息的回调函数
    static int recv_msg(struct nl_msg* msg, void* arg);

    // 接收一次响应消息
    bool recv_reply_once();

    static log_info_queue& get_log_info_queue() { return log_info_queue_; };

   private:
    std::string family_name_;               // Netlink family 名称
    struct nl_sock* sock_;                  // Netlink socket
    int family_id_;                         // family id（通过名字解析得到）
    static log_info_queue log_info_queue_;  // 日志信息队列
};

#endif
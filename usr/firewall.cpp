
#include <iostream>
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"

// todo 还有时间和内容负载没有测试

int main(int argc, char* argv[]) {
    cmd_parser parser;
    netlink_tool netlink_tool("myfirewall");
    parser.get_parser().parse_check(argc, argv);
    bool ret = parser.parse_args((argc - 1) / 2);
    if (!ret) {
        exit(0);
    }
    auto buffer_msg = parser.get_msg_buffer();
    std::cout << "size of buffer msg:" << buffer_msg.size() << std::endl;
    ret = netlink_tool.init();
    if (!ret) {
        std::cout << "netlink_tool init fail'\n'";
        exit(0);
    }
    ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(), 1, 1);
    if (!ret) {
        std::cout << "netlink_tool send fail'\n'";
        exit(0);
    }
    // todo 做一下日志打点测试
}
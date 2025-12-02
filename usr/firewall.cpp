
#include <iostream>
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"

// todo 还有时间和内容负载没有测试

int main(int argc, char* argv[]) {
    cmd_parser parser;

    // 初始化netlink工具
    netlink_tool netlink_tool("myfirewall");
    auto ret = netlink_tool.init();
    if (!ret) {
        std::cout << "netlink_tool init fail'\n'";
        exit(0);
    }
    parser.get_parser().parse_check(argc, argv);

    if (parser.get_parser().exist("add")) {
        ret = parser.parse_args((argc - 3) / 2);
        if(!ret){
            exit(0);
        }
        auto buffer_msg = parser.get_msg_buffer();
        std::cout << "size of buffer msg:" << buffer_msg.size() << std::endl;

        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(), 1,
                                       1);
        if (!ret) {
            std::cout << "netlink_tool send fail'\n'";
            exit(0);
        }

    } else if (parser.get_parser().exist("del")) {
        // 空着
    } else if (parser.get_parser().exist("mode")) {
        auto mode = parser.get_parser().get<std::string>("mode");
        ret = netlink_tool.send_buffer(mode.data(), mode.length(), 2, 1);
        if (!ret) {
            std::cout << "netlink_tool send fail'\n'";
            exit(0);
        }
    } else if (parser.get_parser().exist("list")) {
        ret = netlink_tool.send_buffer("", 0, 3, 1);
        if (!ret) {
            std::cout << "netlink_tool send fail'\n'";
            exit(0);
        }
        ret = (int)netlink_tool.recv_once();
        if (!ret) {
            std::cout << "netlink_tool recv fail'\n'";
            exit(0);
        }
    }
}
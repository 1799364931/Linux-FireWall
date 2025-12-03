
#include <iostream>
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"

bool check_ret(int ret) {
    if (!ret) {
        std::abort();
        // printf("FAIL");
    }
}

int main(int argc, char* argv[]) {
    cmd_parser parser;

    // 初始化netlink工具
    netlink_tool netlink_tool("myfirewall");
    auto ret = netlink_tool.init();
    check_ret(ret);
    parser.get_parser().parse_check(argc, argv);

    if (parser.get_parser().exist("add")) {
        ret = parser.parse_args((argc - 3) / 2);
        check_ret(ret);
        auto buffer_msg = parser.get_msg_buffer();
        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(), 1,
                                       1);
        check_ret(ret);
    } else if (parser.get_parser().exist("del")) {
        auto del_ids =
            parser.del_ids_parse(parser.get_parser().get<std::string>("del"));
        check_ret(del_ids.has_value());
        ret = netlink_tool.send_buffer(
            (char*)del_ids.value().data(),
            del_ids.value().size() * sizeof(uint32_t), 5, 1);

        check_ret(ret);

    } else if (parser.get_parser().exist("mode")) {
        auto mode = parser.get_parser().get<std::string>("mode");
        ret = netlink_tool.send_buffer(mode.data(), mode.length(), 2, 1);
        check_ret(ret);

    } else if (parser.get_parser().exist("list")) {
        ret = netlink_tool.send_buffer("", 0, 3, 1);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    }
}
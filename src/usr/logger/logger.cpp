
#include <iostream>
#include "../controller/netlink_tool/netlink_tool.h"

void check_ret(int ret) {
    if (!ret) {
        std::abort();
    }
}

int main() {
    // 一直获取信息
    // 初始化netlink工具
    netlink_tool netlink_tool("myfirewall");
    auto ret = netlink_tool.init();
    check_ret(ret);

    netlink_tool.send_buffer("", 0, CMD_LOGGING_REGISTER, ATTR_BUF);
    // 后面一直接受即可

    while (true) {
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    }
}

#include <chrono>
#include <iostream>
#include <thread>
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

    // auto recv_func = [&] {
    //     while (true) {
    //         // std::this_thread::sleep_for(std::chrono::seconds(1));
    //         ret = (int)netlink_tool.recv_reply_once();
    //         check_ret(ret);
    //     }
    // };

    std::thread recv_thread([&] {
        while (true) {
            // std::this_thread::sleep_for(std::chrono::seconds(1));
            ret = (int)netlink_tool.recv_reply_once();
            check_ret(ret);
        }
    });

    std::thread print_thread([&] {
        while (true) {
            std::vector<std::string> logs;
            netlink_tool.get_log_info_queue().fetch_logs(logs);
            for (auto& log : logs) {
                std::cout << log << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    });

    recv_thread.join();
    print_thread.join();


}
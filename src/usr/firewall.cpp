// usr/firewall.cpp
#include <iostream>
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"

void check_ret(int ret) {
    if (!ret) {
        std::cerr << "ERROR: Operation failed!" << std::endl;
        std::abort();
    }
}

int main(int argc, char* argv[]) {
    std::cout << "[DEBUG] main() called with argc = " << argc << std::endl;
    for (int i = 0; i < argc; i++) {
        std::cout << "[DEBUG] argv[" << i << "] = " << argv[i] << std::endl;
    }
    
    cmd_parser parser;
    
    // 初始化netlink工具
    netlink_tool netlink_tool("myfirewall");
    auto ret = netlink_tool.init();
    check_ret(ret);
    
    parser.get_parser().parse_check(argc, argv);
    
    // 打印所有识别到的命令
    std::cout << "[DEBUG] Checking for commands..." << std::endl;
    std::cout << "[DEBUG] exist(\"add\") = " << parser.get_parser().exist("add") << std::endl;
    std::cout << "[DEBUG] exist(\"del\") = " << parser.get_parser().exist("del") << std::endl;
    std::cout << "[DEBUG] exist(\"list\") = " << parser.get_parser().exist("list") << std::endl;
    std::cout << "[DEBUG] exist(\"mode\") = " << parser.get_parser().exist("mode") << std::endl;
    std::cout << "[DEBUG] exist(\"add-rate-limit\") = " << parser.get_parser().exist("add-rate-limit") << std::endl;
    std::cout << "[DEBUG] exist(\"del-rate-limit\") = " << parser.get_parser().exist("del-rate-limit") << std::endl;
    std::cout << "[DEBUG] exist(\"list-rate-limit\") = " << parser.get_parser().exist("list-rate-limit") << std::endl;
    std::cout << "[DEBUG] exist(\"reset-rate-limit-stats\") = " << parser.get_parser().exist("reset-rate-limit-stats") << std::endl;
    
    // ============ 原有的规则命令处理 ============
    if (parser.get_parser().exist("add")) {
        std::cout << "[DEBUG] Executing: add rule" << std::endl;
        ret = parser.parse_args((argc - 3) / 2);
        check_ret(ret);
        auto buffer_msg = parser.get_msg_buffer();
        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(),
                                       CMD_ADD_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("del")) {
        std::cout << "[DEBUG] Executing: del rule" << std::endl;
        auto del_ids =
            parser.del_ids_parse(parser.get_parser().get<std::string>("del"));
        check_ret(del_ids.has_value());
        ret = netlink_tool.send_buffer(
            (char*)del_ids.value().data(),
            del_ids.value().size() * sizeof(uint32_t), CMD_DEL_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("mode")) {
        std::cout << "[DEBUG] Executing: mode" << std::endl;
        auto mode = parser.get_parser().get<std::string>("mode");
        ret = netlink_tool.send_buffer(mode.data(), mode.length(),
                                       CMD_CHANGE_MOD, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("list")) {
        std::cout << "[DEBUG] Executing: list rule" << std::endl;
        ret = netlink_tool.send_buffer("", 0, CMD_LIST_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } 
    // ============ 新增：Rate Limit 命令处理 ============
    else if (parser.get_parser().exist("add-rate-limit")) {
        std::cout << "[DEBUG] Executing: add-rate-limit" << std::endl;
        ret = parser.parse_rate_limit_args();
        check_ret(ret);
        auto buffer_msg = parser.get_rate_limit_msg_buffer();
        
        std::cout << "[DEBUG] Buffer size: " << buffer_msg.size() << " bytes" << std::endl;
        
        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(),
                                       CMD_ADD_RATE_LIMIT, ATTR_BUF);
        if (!ret) {
            std::cerr << "[ERROR] Failed to send buffer" << std::endl;
            return 1;
        }
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("del-rate-limit")) {
        std::cout << "[DEBUG] Executing: del-rate-limit" << std::endl;
        auto rule_id = parser.parse_rule_id();
        check_ret(rule_id.has_value());
        
        ret = netlink_tool.send_buffer(
            (char*)&rule_id.value(),
            sizeof(uint32_t), CMD_DEL_RATE_LIMIT, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("list-rate-limit")) {
        std::cout << "[DEBUG] Executing: list-rate-limit" << std::endl;
        ret = netlink_tool.send_buffer("", 0, CMD_LIST_RATE_LIMIT, ATTR_BUF);
        check_ret(ret);
        std::cout << "[DEBUG] About to call recv_once()" << std::endl;
        ret = (int)netlink_tool.recv_once();
        std::cout << "[DEBUG] recv_once() returned " << ret << std::endl;
        check_ret(ret);
    } else if (parser.get_parser().exist("reset-rate-limit-stats")) {
        std::cout << "[DEBUG] Executing: reset-rate-limit-stats" << std::endl;
        auto rule_id = parser.parse_rule_id();
        check_ret(rule_id.has_value());
        
        ret = netlink_tool.send_buffer(
            (char*)&rule_id.value(),
            sizeof(uint32_t), CMD_RESET_RATE_LIMIT_STATS, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_once();
        check_ret(ret);
    } else {
        std::cout << "[ERROR] Unknown command!" << std::endl;
        std::cout << "[ERROR] Available commands:" << std::endl;
        std::cout << "  add, del, list, mode" << std::endl;
        std::cout << "  add-rate-limit, del-rate-limit, list-rate-limit, reset-rate-limit-stats" << std::endl;
    }
    
    return 0;
}
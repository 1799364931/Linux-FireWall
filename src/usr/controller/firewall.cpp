// usr/firewall.cpp
#include <iostream>
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"

void check_ret(int ret) {
    if (!ret) {
        std::abort();
    }
}

int main(int argc, char* argv[]) {
    cmd_parser parser;

    // 初始化netlink工具
    netlink_tool netlink_tool("myfirewall");
    auto ret = netlink_tool.init();
    check_ret(ret);

    parser.get_parser().parse_check(argc, argv);

    // ============ 原有的规则命令处理 ============
    if (parser.get_parser().exist("add")) {
        // 减去 ./firewall --add --drop --out?
        uint32_t condition_cnt = (argc - 3) / 2;
        if (parser.get_parser().exist("out")) {
            condition_cnt = (argc - 4) / 2;
        }
        ret = parser.parse_args(condition_cnt);
        check_ret(ret);
        auto buffer_msg = parser.get_msg_buffer();
        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(),
                                       CMD_ADD_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("del")) {
        auto del_ids =
            parser.del_ids_parse(parser.get_parser().get<std::string>("del"));
        check_ret(del_ids.has_value());
        ret = netlink_tool.send_buffer(
            (char*)del_ids.value().data(),
            del_ids.value().size() * sizeof(uint32_t), CMD_DEL_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("mode")) {
        auto mode = parser.get_parser().get<std::string>("mode");
        if (parser.get_parser().exist("out")) {
            mode += "out";
        }
        ret = netlink_tool.send_buffer(mode.data(), mode.length(),
                                       CMD_CHANGE_MOD, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("list")) {
        ret = netlink_tool.send_buffer("", 0, CMD_LIST_RULE, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    }
    // ============ 新增：Rate Limit 命令处理 ============
    else if (parser.get_parser().exist("add-rate-limit")) {
        ret = parser.parse_rate_limit_args();
        check_ret(ret);
        auto buffer_msg = parser.get_rate_limit_msg_buffer();

        ret = netlink_tool.send_buffer(buffer_msg.data(), buffer_msg.size(),
                                       CMD_ADD_RATE_LIMIT, ATTR_BUF);
        if (!ret) {
            return 1;
        }
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("del-rate-limit")) {
        auto rule_id = parser.parse_rule_id();
        check_ret(rule_id.has_value());

        ret =
            netlink_tool.send_buffer((char*)&rule_id.value(), sizeof(uint32_t),
                                     CMD_DEL_RATE_LIMIT, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("list-rate-limit")) {
        ret = netlink_tool.send_buffer("", 0, CMD_LIST_RATE_LIMIT, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    } else if (parser.get_parser().exist("reset-rate-limit-stats")) {
        auto rule_id = parser.parse_rule_id();
        check_ret(rule_id.has_value());

        ret =
            netlink_tool.send_buffer((char*)&rule_id.value(), sizeof(uint32_t),
                                     CMD_RESET_RATE_LIMIT_STATS, ATTR_BUF);
        check_ret(ret);
        ret = (int)netlink_tool.recv_reply_once();
        check_ret(ret);
    }

    return 0;
}
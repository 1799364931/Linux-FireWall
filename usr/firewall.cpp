
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"
#include <iostream>



int main(int argc, char* argv[]) {
    cmd_parser parser;
    netlink_tool netlink_tool("myfirewall");
    parser.get_parser().parse_check(argc,argv);
    parser.parse_args(argc);
    auto buffer_msg =  parser.get_msg_buffer();
    std::cout<<buffer_msg.size();
    netlink_tool.send_buffer(buffer_msg.data(),buffer_msg.size(),1,1);
    
    //todo 做一下日志打点测试
    
}
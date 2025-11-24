
#include "cmd_parser/cmd_parser.h"
#include "netlink_tool/netlink_tool.h"


int main(int argc, char* argv[]) {
    cmd_parser parser;
    netlink_tool netlink_tool();
    parser.get_parser().parse_check(argc,argv);
}
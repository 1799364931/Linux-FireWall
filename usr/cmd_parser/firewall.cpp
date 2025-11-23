
#include "cmd_parser.h"

int main(int argc, char* argv[]) {
    cmd_parser parser;
    parser.get_parser().parse_check(argc,argv);
}
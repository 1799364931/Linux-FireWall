
#ifndef _CMD_PARSER_H
#define _CMD_PARSER_H

#include "cmdline.h"

class cmd_parser {
   public:
    cmd_parser() { this->build_parser(); }

    cmdline::parser& get_parser() { return this->parser_; }

   private:

    static const std::vector<std::string> proto;

    void build_parser();

    void is_vaild();

    bool ip_vaild(std::string ip_str);

    bool mac_vaild(std::string mac_str);

    bool proto_vaild(std::string proto_str);

    bool time_vaild(std::string time_str);

    bool content_vaild(std::string contents);

    cmdline::parser parser_;
};

#endif

#ifndef _CMD_PARSER_H
#define _CMD_PARSER_H

#include <netinet/in.h>
#include <cctype>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>
#include "cmdline.h"
#include "../../public_structs/match_condition_msg.h"
#include "../../public_structs/rule_bitmap.h"
class cmd_parser {
   public:
    cmd_parser() { this->build_parser(); }

    cmdline::parser& get_parser() { return this->parser_; }

    void parse_args(uint32_t argc);

    std::vector<char> get_msg_buffer() {
        std::vector<char> msg_buffer(rule_entry_msg_size_ + buffer_.size());
        std::cout<<"buffer size:" <<buffer_.size()<<std::endl;
        std::memcpy(msg_buffer.data(),entry_,rule_entry_msg_size_);
        std::memcpy(msg_buffer.data()+rule_entry_msg_size_,buffer_.data(),buffer_.size());
        return msg_buffer;
    };

   private:
    static const std::unordered_map<std::string, uint16_t> protos_;

    void build_parser();

    std::optional<uint32_t> ip_parse(std::string ip_str);

    std::optional<std::vector<char>> mac_parse(std::string mac_str);

    std::optional<uint16_t> proto_parse(std::string proto_str);

    std::optional<
        std::vector<std::pair<std::pair<int, int>, std::pair<int, int>>>>
    time_parse(std::string time_str);

    std::optional<std::vector<std::string>> content_parse(std::string contents);

    cmdline::parser parser_;

    uint32_t buffer_offset_ = 0;
    uint32_t buffer_len_ = 0;
    struct rule_entry_msg* entry_ = 0;
    std::vector<char> buffer_;
    uint32_t rule_entry_msg_size_ = 0;
};

#endif
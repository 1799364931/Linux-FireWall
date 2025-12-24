// usr/cmd_parser/cmd_parser.h
#ifndef _CMD_PARSER_H
#define _CMD_PARSER_H
#include <netinet/in.h>
#include <cctype>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>
#include "../../../public_structs/match_condition_msg.h"
#include "../../../public_structs/rule_bitmap.h"
#include "cmdline.h"

// ============ Rate Limiter 相关结构体 ============
struct rate_limit_entry_msg {
    uint32_t refill_rate;      /* 令牌补充速率（pps） */
    uint32_t max_tokens;       /* 最大令牌数 */
    uint32_t src_ip;           /* 源IP（0表示不限制） */
    uint32_t dst_ip;           /* 目标IP（0表示不限制） */
    uint16_t src_port;         /* 源端口（0表示不限制） */
    uint16_t dst_port;         /* 目标端口（0表示不限制） */
    uint32_t priority;         /* 优先级 */
} __attribute__((packed));

class cmd_parser {
   public:
    cmd_parser() { this->build_parser(); }
    ~cmd_parser() { free(entry_); }
    cmdline::parser& get_parser() { return this->parser_; }
    
    // ============ 原有的规则解析方法 ============
    bool parse_args(uint32_t argc);
    std::vector<char> get_msg_buffer() {
        std::vector<char> msg_buffer(rule_entry_msg_size_ + buffer_.size());
        std::cout << "buffer size:" << buffer_.size() << std::endl;
        std::memcpy(msg_buffer.data(), entry_, rule_entry_msg_size_);
        std::memcpy(msg_buffer.data() + rule_entry_msg_size_, buffer_.data(),
                    buffer_.size());
        return msg_buffer;
    };
    std::optional<std::vector<uint32_t>> del_ids_parse(std::string del_str);
    
    // ============ 新增：Rate Limit 解析方法 ============
    bool parse_rate_limit_args();
    std::vector<char> get_rate_limit_msg_buffer() {
        std::vector<char> msg_buffer(sizeof(struct rate_limit_entry_msg));
        std::memcpy(msg_buffer.data(), &rate_limit_entry_, 
                    sizeof(struct rate_limit_entry_msg));
        return msg_buffer;
    };
    std::optional<uint32_t> parse_rule_id();

   private:
    static const std::unordered_map<std::string, uint16_t> protos_;
    void build_parser();
    
    // ============ 原有的解析函数 ============
    std::optional<uint32_t> ip_parse(std::string ip_str);
    std::optional<std::vector<char>> mac_parse(std::string mac_str);
    std::optional<uint16_t> proto_parse(std::string proto_str);
    std::optional<
        std::vector<std::pair<std::pair<int, int>, std::pair<int, int>>>>
    time_parse(std::string time_str);
    std::optional<std::vector<std::string>> content_parse(std::string contents);
    
    // ============ 原有的成员变量 ============
    cmdline::parser parser_;
    uint32_t buffer_offset_ = 0;
    uint32_t buffer_len_ = 0;
    struct rule_entry_msg* entry_ = 0;
    std::vector<char> buffer_;
    uint32_t rule_entry_msg_size_ = 0;
    
    // ============ 新增：Rate Limit 成员变量 ============
    struct rate_limit_entry_msg rate_limit_entry_ = {0};
};

#endif
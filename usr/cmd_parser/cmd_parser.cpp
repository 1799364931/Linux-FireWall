#include "cmd_parser.h"
#include <arpa/inet.h>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::string token;
    std::stringstream ss(str);

    while (std::getline(ss, token, delimiter)) {
        if (!token.empty()) {
            result.push_back(token);
        }
    }

    return result;
}

void cmd_parser::build_parser() {
    parser_.add<std::string>("src-ip", 0, "src ip", false);
    parser_.add<std::string>("dst-ip", 0, "dst ip", false);
    parser_.add<std::string>("src-ip-mask", 0, "src ip mask", false);
    parser_.add<std::string>("dst-ip-mask", 0, "dst ip mask", false);
    parser_.add<int>("src-port", 0, "src port", false, 80,
                     cmdline::range(1, 65535));
    parser_.add<int>("dst-port", 0, "dst port", false, 80,
                     cmdline::range(1, 65535));
    parser_.add<std::string>("src-mac", 0, "src mac", false);
    parser_.add<std::string>("dst-mac", 0, "dst mac", false);
    parser_.add<std::string>("proto", 0, "ipv4 proto", false);
    //
    parser_.add<std::string>("time-drop", 0, "drop the data package at time",
                             false);
    parser_.add<std::string>("time-accept", 0,
                             "accept the data package at time", false);
    parser_.add<int>("est", 0, "only the est state data package accept", false,
                     0);
    parser_.add<std::string>(
        "content", 0, "filter the package whose payload contains content",
        false);
    parser_.add<std::string>("interface", 0, "interface", false);

    parser_.add<std::string>("mode", 0, "mode", false);
    parser_.add("add", 0, "add");
    parser_.add("del", 0, "del");
    parser_.add("list", 0, "list");
    parser_.add("drop", 0, "add black list rule");
    parser_.add("accept", 0, "add white list rule");
}

std::optional<uint32_t> cmd_parser::ip_parse(std::string ip_str) {
    std::stringstream ss(ip_str);
    std::string segment;
    int count = 0;
    unsigned int result = 0;

    while (std::getline(ss, segment, '.')) {
        // 段不能为空
        if (segment.empty())
            return std::nullopt;

        // 检查是否全是数字
        for (char c : segment) {
            if (!isdigit(static_cast<unsigned char>(c)))
                return std::nullopt;
        }

        // 转换成整数并检查范围
        int num = std::stoi(segment);
        if (num < 0 || num > 255)
            return std::nullopt;

        // 大端序拼接：左移 8 位再加上当前段
        result = (result << 8) | static_cast<unsigned int>(num);

        count++;
    }

    // 必须正好 4 段
    if (count != 4)
        return std::nullopt;

    return result;
}

std::optional<std::vector<char>> cmd_parser::mac_parse(std::string mac_str) {
    // 允许分隔符 ':' 或 '-'
    char delimiter = (mac_str.find(':') != std::string::npos) ? ':' : '-';

    std::stringstream ss(mac_str);
    std::string segment;
    std::vector<char> mac_bytes;
    int count = 0;

    while (std::getline(ss, segment, delimiter)) {
        // 每段必须是 2 个十六进制字符
        if (segment.size() != 2)
            return std::nullopt;

        // 检查是否都是十六进制字符
        for (char c : segment) {
            if (!isxdigit(static_cast<unsigned char>(c)))
                return std::nullopt;
        }

        // 转换成整数
        int value = std::stoi(segment, nullptr, 16);
        mac_bytes.push_back(static_cast<char>(value));

        count++;
    }

    // 必须正好 6 段
    if (count != 6)
        return std::nullopt;

    return mac_bytes;
}

const std::unordered_map<std::string, uint16_t> cmd_parser::protos_ = {
    {"tcp", IPPROTO_TCP},
    {"udp", IPPROTO_UDP},
    {"icmp", IPPROTO_ICMP}};

std::optional<uint16_t> cmd_parser::proto_parse(std::string proto_str) {
    auto it = protos_.find(proto_str);
    if (it != protos_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// "xx:xx xx:xx"
std::optional<std::vector<std::pair<std::pair<int, int>, std::pair<int, int>>>>
cmd_parser::time_parse(std::string time_str) {
    // 提取内部所有被引号包裹的子串
    std::vector<std::string> groups;
    groups = split_string(time_str, ' ');

    if (groups.empty()) {
        return std::nullopt;
    }
    std::vector<std::pair<std::pair<int, int>, std::pair<int, int>>> result;

    if (groups.size() % 2 != 0) {
        // 必须成对出现
        return std::nullopt;
    }

    for (size_t i = 0; i < groups.size(); i += 2) {
        auto parse_time =
            [](const std::string& s) -> std::optional<std::pair<int, int>> {
            int hour, minute;
            char colon;
            std::istringstream iss(s);
            if (!(iss >> hour >> colon >> minute)) {
                return std::nullopt;
            }
            if (colon != ':' || hour < 0 || hour > 23 || minute < 0 ||
                minute > 59) {
                return std::nullopt;
            }
            return std::make_pair(hour, minute);
        };

        auto start = parse_time(groups[i]);
        auto end = parse_time(groups[i + 1]);

        if (!start || !end) {
            return std::nullopt;  // 格式错误或范围非法
        }

        result.push_back({*start, *end});
    }

    if (result.empty()) {
        return std::nullopt;
    }

    return result;
}

std::optional<std::vector<std::string>> cmd_parser::content_parse(
    std::string contents) {
    std::vector<std::string> result = split_string(contents, ' ');

    if (result.empty())
        return std::nullopt;

    return result;
}

bool cmd_parser::parse_args(uint32_t argc) {
    //

    // 构造结构体

    rule_entry_msg_size_ = sizeof(struct match_condition_msg) * argc +
                           sizeof(struct rule_entry_msg);

    entry_ = (struct rule_entry_msg*)malloc(rule_entry_msg_size_);
    if (entry_ == NULL) {
        std::cout << "memory limit! malloc fail" << std::endl;
        return false;
    }

    memset(entry_, 0, rule_entry_msg_size_);

    if (!(parser_.exist("drop") || parser_.exist("accept"))) {
        std::cout << "except --drop or --accept to define rule" << std::endl;
        return false;
    }

    if (parser_.exist("drop")) {
        entry_->bitmap |= RULE_BLACK;
    }

    // ip 处理
    if (parser_.exist("src-ip")) {
        auto ip = ip_parse(parser_.get<std::string>("src-ip"));
        if (ip.has_value()) {
            entry_->conditions[entry_->condition_count].src_ip = ip.value();

            entry_->conditions[entry_->condition_count].match_type =
                RULE_SRC_IP;
            entry_->bitmap |= RULE_SRC_IP;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg src-ip parse fail" << std::endl;
            return false;
        }
    }

    if (parser_.exist("dst-ip")) {
        auto ip = ip_parse(parser_.get<std::string>("dst-ip"));
        if (ip.has_value()) {
            entry_->conditions[entry_->condition_count].dst_ip = ip.value();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_DST_IP;
            entry_->bitmap |= RULE_DST_IP;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg dst-ip parse fail" << std::endl;
            return false;
        }
    }

    if (parser_.exist("src-ip-mask")) {
        auto ip = ip_parse(parser_.get<std::string>("src-ip-mask"));
        if (ip.has_value()) {
            entry_->conditions[entry_->condition_count].src_mask_ip =
                ip.value();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_SRC_IP_MASK;
            entry_->bitmap |= RULE_SRC_IP_MASK;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg src-ip-mask parse fail" << std::endl;
            return false;
        }
    }

    if (parser_.exist("dst-ip-mask")) {
        auto ip = ip_parse(parser_.get<std::string>("dst-ip-mask"));
        if (ip.has_value()) {
            entry_->conditions[entry_->condition_count].dst_mask_ip =
                ip.value();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_DST_IP_MASK;
            entry_->bitmap |= RULE_DST_IP_MASK;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg dst-ip-mask parse fail" << std::endl;

            return false;
        }
    }

    // port 处理
    if (parser_.exist("src-port")) {
        auto port = parser_.get<int>("src-port");
        if (0 <= port && port <= 65535) {
            entry_->conditions[entry_->condition_count].src_port = htons(port);
            entry_->conditions[entry_->condition_count].match_type =
                RULE_SRC_PORT;
            entry_->bitmap |= RULE_SRC_PORT;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg src-port parse fail" << std::endl;

            return false;
        }
    }

    if (parser_.exist("dst-port")) {
        auto port = parser_.get<int>("dst-port");
        if (0 <= port && port <= 65535) {
            entry_->conditions[entry_->condition_count].dst_port = htons(port);
            entry_->conditions[entry_->condition_count].match_type =
                RULE_DST_PORT;
            entry_->bitmap |= RULE_DST_PORT;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg dst-port parse fail" << std::endl;

            return false;
        }
    }

    // 处理mac
    if (parser_.exist("src-mac")) {
        auto mac = mac_parse(parser_.get<std::string>("src-mac"));
        if (mac.has_value()) {
            memcpy(entry_->conditions[entry_->condition_count].src_mac,
                   mac.value().data(), MAC_LENGTH);
            entry_->conditions[entry_->condition_count].match_type =
                RULE_SRC_MAC;
            entry_->bitmap |= RULE_SRC_MAC;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg src-mac parse fail" << std::endl;

            return false;
        }
    }

    if (parser_.exist("dst-mac")) {
        auto mac = mac_parse(parser_.get<std::string>("dst-mac"));
        if (mac.has_value()) {
            memcpy(entry_->conditions[entry_->condition_count].dst_mac,
                   mac.value().data(), MAC_LENGTH);
            entry_->conditions[entry_->condition_count].match_type =
                RULE_DST_MAC;
            entry_->bitmap |= RULE_DST_MAC;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg dst-mac parse fail" << std::endl;
            return false;
        }
    }

    // 处理proto
    if (parser_.exist("proto")) {
        auto proto = proto_parse(parser_.get<std::string>("proto"));
        if (proto.has_value()) {
            entry_->conditions[entry_->condition_count].ipv4_protocol =
                proto.value();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_IPV4_PROTOCOL;
            entry_->bitmap |= RULE_IPV4_PROTOCOL;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg proto parse fail" << std::endl;
            return false;
        }
    }

    // 处理状态连接过滤开关
    if (parser_.exist("est")) {
        entry_->conditions[entry_->condition_count].match_type =
            RULE_STATE_POLICY_DENY_ALL_NEW;
        entry_->bitmap |= RULE_STATE_POLICY_DENY_ALL_NEW;
        entry_->condition_count++;
    }

    // 处理content
    if (parser_.exist("content")) {
        auto contents = content_parse(parser_.get<std::string>("content"));
        // buffer布局
        // [字符串个数|4字节][字符串1长度][字符串1][字符串2长度][字符串2].....
        //
        // 序列化
        if (contents.has_value()) {
            uint32_t total_size = sizeof(uint32_t) + contents.value().size();
            for (auto& str : contents.value()) {
                total_size += str.length() + sizeof(uint32_t);
            }
            buffer_.resize(total_size);
            auto ptr = buffer_.data();
            int len = static_cast<int>(contents.value().size());
            std::memcpy(ptr, &len, sizeof(len));
            ptr += sizeof(int);
            for (auto& str : contents.value()) {
                len = static_cast<int>(str.length());
                std::memcpy(ptr, &len, sizeof(len));
                ptr += sizeof(int);
                std::memcpy(ptr, str.data(), str.length());
                ptr += str.length();
            }
            entry_->conditions[entry_->condition_count].buffer_offset =
                buffer_offset_;
            entry_->conditions[entry_->condition_count].buffer_len = total_size;
            entry_->conditions[entry_->condition_count].match_type =
                RULE_CONTENT;
            entry_->bitmap |= RULE_CONTENT;
            entry_->condition_count++;
        } else {
            std::cout << "arg content parse fail" << std::endl;

            // 失败处理
            return false;
        }
    }

    // 处理time
    if (parser_.exist("time-drop")) {
        // [时间对个数] [HH:MM][HH:MM] 一个时间对2*4 = 8字节
        auto times = time_parse(parser_.get<std::string>("time-drop"));
        if (times.has_value()) {
            buffer_.resize(buffer_.size() + sizeof(uint32_t) +
                           sizeof(uint32_t) * 4 * times.value().size());
            auto ptr = buffer_.data() + buffer_offset_;
            auto number_cpy = [&](uint32_t num) {
                uint32_t tmp = num;
                std::memcpy(ptr, &tmp, sizeof(uint32_t));
                ptr += sizeof(uint32_t);
            };
            number_cpy(times.value().size());
            for (auto& time : times.value()) {
                auto [h, m] = time;
                number_cpy(h.first);
                number_cpy(h.second);
                number_cpy(m.first);
                number_cpy(m.second);
            }
            //
            entry_->conditions[entry_->condition_count].buffer_len =
                sizeof(uint32_t) + sizeof(uint32_t) * 4 * times.value().size();
            entry_->conditions[entry_->condition_count].buffer_offset =
                buffer_offset_;
            buffer_offset_ = buffer_.size();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_TIME_DROP;
            entry_->bitmap |= RULE_TIME_DROP;
            entry_->condition_count++;
        } else {
            // 失败处理
            std::cout << "arg time-drop parse fail" << std::endl;

            return false;
        }
    }
    if (parser_.exist("time-accept")) {
        // [时间对个数] [HH:MM][HH:MM] 一个时间对2*4 = 8字节
        auto times = time_parse(parser_.get<std::string>("time-accept"));
        if (times.has_value()) {
            buffer_.resize(buffer_.size() + sizeof(uint32_t) +
                           sizeof(uint32_t) * 4 * times.value().size());
            auto ptr = buffer_.data() + buffer_offset_;
            auto number_cpy = [&](uint32_t num) {
                uint32_t tmp = num;
                std::memcpy(ptr, &tmp, sizeof(uint32_t));
                ptr += sizeof(uint32_t);
            };
            number_cpy(times.value().size());
            for (auto& time : times.value()) {
                auto [h, m] = time;
                number_cpy(h.first);
                number_cpy(h.second);
                number_cpy(m.first);
                number_cpy(m.second);
            }
            //
            entry_->conditions[entry_->condition_count].buffer_len =
                sizeof(uint32_t) + sizeof(uint32_t) * 4 * times.value().size();
            entry_->conditions[entry_->condition_count].buffer_offset =
                buffer_offset_;
            buffer_offset_ = buffer_.size();
            entry_->conditions[entry_->condition_count].match_type =
                RULE_TIME_ACCEPT;
            entry_->bitmap |= RULE_TIME_ACCEPT;
            entry_->condition_count++;

        } else {
            // 失败处理
            std::cout << "arg time-accept parse fail" << std::endl;
            return false;
        }
    }

    // 处理interface
    if (parser_.exist("interface")) {
        // [长度][字符串]
        auto interface = parser_.get<std::string>("interface");
        buffer_.resize(buffer_.size() + interface.length() + sizeof(uint32_t));
        auto ptr = buffer_.data() + buffer_offset_;
        uint32_t len = interface.length();
        std::memcpy(ptr, &len, sizeof(uint32_t));

        ptr += sizeof(uint32_t);
        std::memcpy(ptr, interface.data(), interface.length());
        entry_->conditions[entry_->condition_count].buffer_offset =
            buffer_offset_;
        buffer_offset_ = buffer_.size();
        entry_->conditions[entry_->condition_count].buffer_len =
            interface.length() + sizeof(uint32_t);
        entry_->conditions[entry_->condition_count].match_type = RULE_INTERFACE;
        entry_->bitmap |= RULE_INTERFACE;
        entry_->condition_count++;
    }
    return true;
}
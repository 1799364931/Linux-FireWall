#include "cmd_parser.h"
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

void cmd_parser::build_parser() {
    parser_.add<std::string>("src-ip", 0, "src ip", false);
    parser_.add<std::string>("dst-ip", 0, "dst ip", false);
    parser_.add<std::string>("src-ip-mask", 0, "src ip mask", false);
    parser_.add<std::string>("src-ip-mask", 0, "src ip mask", false);
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
    parser_.add("est", 0, "only the est state data package accept");
    parser_.add<std::string>(
        "content", 0, "filter the package whose payload contains content",
        false);
    parser_.add<std::string>("interface", 0, "interface", false);
}

std::optional<u_int32_t> cmd_parser::ip_parse(std::string ip_str) {
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

const std::unordered_map<std::string, u_int16_t> cmd_parser::protos_ = {
    {"tcp", IPPROTO_TCP},
    {"udp", IPPROTO_UDP},
    {"icmp", IPPROTO_ICMP}};

std::optional<u_int16_t> cmd_parser::proto_parse(std::string proto_str) {
    auto it = protos_.find(proto_str);
    if (it != protos_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// "xx:xx xx:xx"
std::optional<std::vector<std::pair<int, int>>> cmd_parser::time_parse(
    std::string time_str) {
    // 去掉首尾引号
    if (time_str.size() >= 2 && time_str.front() == '"' &&
        time_str.back() == '"') {
        time_str = time_str.substr(1, time_str.size() - 2);
    } else {
        return std::nullopt;  // 必须有双引号
    }

    std::stringstream ss(time_str);
    std::string t1, t2;

    // 分割两个时间
    if (!(ss >> t1 >> t2))
        return std::nullopt;

    auto parse_time =
        [](const std::string& t) -> std::optional<std::pair<int, int>> {
        if (t.size() != 5 || t[2] != ':')
            return std::nullopt;
        if (!isdigit(static_cast<unsigned char>(t[0])) ||
            !isdigit(static_cast<unsigned char>(t[1])) ||
            !isdigit(static_cast<unsigned char>(t[3])) ||
            !isdigit(static_cast<unsigned char>(t[4])))
            return std::nullopt;

        int hour = std::stoi(t.substr(0, 2));
        int minute = std::stoi(t.substr(3, 2));

        if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
            return std::nullopt;

        return std::make_pair(hour, minute);
    };

    auto p1 = parse_time(t1);
    auto p2 = parse_time(t2);

    if (!p1 || !p2)
        return std::nullopt;

    std::vector<std::pair<int, int>> result;
    result.push_back(*p1);
    result.push_back(*p2);

    return result;
}

std::optional<std::vector<std::string>> cmd_parser::content_parse(
    std::string contents) {
    size_t i = 0;
    std::vector<std::string> result;

    // 去掉首尾引号（整体必须包裹）
    if (contents.size() >= 2 && contents.front() == '"' &&
        contents.back() == '"') {
        contents = contents.substr(1, contents.size() - 2);
    } else {
        return std::nullopt;  // 必须有双引号
    }

    while (i < contents.size()) {
        // 跳过前导空格
        while (i < contents.size() &&
               isspace(static_cast<unsigned char>(contents[i]))) {
            i++;
        }

        // 必须以双引号开头
        if (i >= contents.size() || contents[i] != '"') {
            return std::nullopt;
        }
        i++;

        // 找到下一个双引号
        size_t end = contents.find('"', i);
        if (end == std::string::npos) {
            return std::nullopt;
        }

        // 提取内容（可以为空字符串）
        std::string token = contents.substr(i, end - i);
        result.push_back(token);

        // 移动到结束引号之后
        i = end + 1;

        // 跳过结尾空格，继续下一个
        while (i < contents.size() &&
               isspace(static_cast<unsigned char>(contents[i]))) {
            i++;
        }
    }

    // 至少要有一个合法的 "xxx"
    if (result.empty())
        return std::nullopt;

    return result;
}

void cmd_parser::parse_args(){
    // 构造结构体
    
    if(parser_.exist("src-ip")){
        
    }
}
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

bool cmd_parser::ip_vaild(std::string ip_str) {
    std::stringstream ss(ip_str);
    std::string segment;
    int count = 0;

    while (std::getline(ss, segment, '.')) {
        // 段不能为空
        if (segment.empty())
            return false;

        // 检查是否全是数字
        for (char c : segment) {
            if (!isdigit(c))
                return false;
        }

        // 转换成整数并检查范围
        int num = std::stoi(segment);
        if (num < 0 || num > 255)
            return false;

        count++;
    }

    return count == 4;
}

bool cmd_parser::mac_vaild(std::string mac_str) {
    // 允许分隔符 ':' 或 '-'
    char delimiter = (mac_str.find(':') != std::string::npos) ? ':' : '-';

    std::stringstream ss(mac_str);
    std::string segment;
    int count = 0;

    while (std::getline(ss, segment, delimiter)) {
        // 每段必须是 2 个十六进制字符
        if (segment.size() != 2)
            return false;

        for (char c : segment) {
            if (!isxdigit(c))
                return false;  // 必须是 0-9 或 A-F/a-f
        }

        count++;
    }

    // 必须正好 6 段
    return count == 6;
}

const std::vector<std::string> cmd_parser::proto = {"tcp", "udp", "icmp"};

bool cmd_parser::proto_vaild(std::string proto_str) {
    for (auto& str : proto) {
        if (str == proto_str) {
            return true;
        }
    }

    return false;
}

// "xx:xx xx:xx"
bool cmd_parser::time_vaild(std::string time_str) {
    // 去掉首尾引号
    if (time_str.size() >= 2 && 
        time_str.front() == '"' && time_str.back() == '"') {
        time_str = time_str.substr(1, time_str.size() - 2);
    } else {
        return false; // 必须有双引号
    }

    std::stringstream ss(time_str);
    std::string t1, t2;

    // 分割两个时间
    if (!(ss >> t1 >> t2)) return false;

    auto check_time = [](const std::string& t) -> bool {
        if (t.size() != 5 || t[2] != ':') return false;
        if (!isdigit(t[0]) || !isdigit(t[1]) || !isdigit(t[3]) || !isdigit(t[4]))
            return false;

        int hour = std::stoi(t.substr(0, 2));
        int minute = std::stoi(t.substr(3, 2));

        return (hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59);
    };

    return check_time(t1) && check_time(t2);
}

bool cmd_parser::content_vaild(std::string contents) {
    size_t i = 0;
    int count = 0;
    // 去掉首尾引号
    if (contents.size() >= 2 && 
        contents.front() == '"' && contents.back() == '"') {
        contents = contents.substr(1, contents.size() - 2);
    } else {
        return false; // 必须有双引号
    }

    while (i < contents.size()) {
        // 跳过前导空格
        while (i < contents.size() && isspace(contents[i])) i++;

        // 必须以双引号开头
        if (i >= contents.size() || contents[i] != '"') return false;
        i++;

        // 找到下一个双引号
        size_t end = contents.find('"', i);
        if (end == std::string::npos) return false;

        // 提取内容（可以为空字符串，但必须存在）
        std::string token = contents.substr(i, end - i);

        // 移动到结束引号之后
        i = end + 1;
        count++;

        // 跳过结尾空格，继续下一个
        while (i < contents.size() && isspace(contents[i])) i++;
    }

    // 至少要有一个合法的 "xxx"
    return count > 0;
}

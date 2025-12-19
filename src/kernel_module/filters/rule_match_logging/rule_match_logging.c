#include "rule_match_logging.h"
#include <linux/inet.h>
#include <net/ip.h>

/**
 * 获取当前系统时间戳（联网时间）
 * 返回格式: "HH:MM:SS.ffffff"
 */
void get_rule_match_timestamp(char* timestamp_buf, size_t buf_size) {
    struct timespec64 ts;
    struct tm tm;
    unsigned long local_time;
    
    // 获取当前时间（包含纳秒精度）
    ktime_get_real_ts64(&ts);
    
    // 转换为本地时间
    local_time = (unsigned long)(ts.tv_sec - (sys_tz.tz_minuteswest * 60));
    time64_to_tm(local_time, 0, &tm);
    
    // 格式化时间戳：HH:MM:SS.ffffff
    snprintf(timestamp_buf, buf_size, "%02d:%02d:%02d.%06ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec / 1000);  // 纳秒转微秒
}

/**
 * 将 IP 地址转换为字符串
 */
static inline void ip_to_string(uint32_t ip, char* str) {
    unsigned char* bytes = (unsigned char*)&ip;
    sprintf(str, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * 获取 TCP 标志位的字符串表示
 */
static inline void get_tcp_flags_string(uint8_t flags, char* flags_str) {
    int offset = 0;
    
    if (flags & TCP_FLAG_SYN)
        offset += sprintf(flags_str + offset, "SYN,");
    if (flags & TCP_FLAG_ACK)
        offset += sprintf(flags_str + offset, "ACK,");
    if (flags & TCP_FLAG_FIN)
        offset += sprintf(flags_str + offset, "FIN,");
    if (flags & TCP_FLAG_RST)
        offset += sprintf(flags_str + offset, "RST,");
    if (flags & TCP_FLAG_PSH)
        offset += sprintf(flags_str + offset, "P.,");
    
    // 删除最后的逗号
    if (offset > 0)
        flags_str[offset - 1] = '\0';
    else
        sprintf(flags_str, "NONE");
}

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08

/**
 * 记录 TCP 数据包信息
 */
static inline void log_rule_match_tcp_packet(uint32_t rule_id,
                                             struct iphdr* iph, 
                                             struct tcphdr* tcph,
                                             const char* action) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    char flags_str[64];
    uint16_t src_port, dst_port;
    uint16_t payload_len;
    
    // 获取时间戳
    get_rule_match_timestamp(timestamp, sizeof(timestamp));
    
    // 转换 IP 地址
    ip_to_string(iph->saddr, src_ip);
    ip_to_string(iph->daddr, dst_ip);
    
    // 转换端口号（网络字节序转本地字节序）
    src_port = ntohs(tcph->source);
    dst_port = ntohs(tcph->dest);
    
    // 获取 TCP 标志位
    get_tcp_flags_string(tcph->fin | (tcph->syn << 1) | (tcph->rst << 2) | 
                         (tcph->psh << 3) | (tcph->ack << 4), flags_str);
    
    // 计算载荷长度
    payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
    
    // 输出日志
    printk(KERN_INFO "%s [RULE_ID:%u] %s TCP %s.%u > %s.%u Flags[%s] seq %u ack %u win %u length %u\n",
           timestamp,
           rule_id,
           action,
           src_ip, src_port,
           dst_ip, dst_port,
           flags_str,
           ntohl(tcph->seq),
           ntohl(tcph->ack_seq),
           ntohs(tcph->window),
           payload_len);
}

/**
 * 记录 UDP 数据包信息
 */
static inline void log_rule_match_udp_packet(uint32_t rule_id,
                                             struct iphdr* iph, 
                                             struct udphdr* udph,
                                             const char* action) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    uint16_t src_port, dst_port;
    
    // 获取时间戳
    get_rule_match_timestamp(timestamp, sizeof(timestamp));
    
    // 转换 IP 地址
    ip_to_string(iph->saddr, src_ip);
    ip_to_string(iph->daddr, dst_ip);
    
    // 转换端口号
    src_port = ntohs(udph->source);
    dst_port = ntohs(udph->dest);
    
    // 输出日志
    printk(KERN_INFO "%s [RULE_ID:%u] %s UDP %s.%u > %s.%u length %u\n",
           timestamp,
           rule_id,
           action,
           src_ip, src_port,
           dst_ip, dst_port,
           ntohs(udph->len));
}

/**
 * 记录 ICMP 数据包信息
 */
static inline void log_rule_match_icmp_packet(uint32_t rule_id,
                                              struct iphdr* iph, 
                                              struct icmphdr* icmph,
                                              const char* action) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    char icmp_type_str[32];
    uint16_t payload_len;
    
    // 获取时间戳
    get_rule_match_timestamp(timestamp, sizeof(timestamp));
    
    // 转换 IP 地址
    ip_to_string(iph->saddr, src_ip);
    ip_to_string(iph->daddr, dst_ip);
    
    // 获取 ICMP 类型的文字描述
    switch (icmph->type) {
        case ICMP_ECHO:
            sprintf(icmp_type_str, "Echo Request");
            break;
        case ICMP_ECHOREPLY:
            sprintf(icmp_type_str, "Echo Reply");
            break;
        case ICMP_DEST_UNREACH:
            sprintf(icmp_type_str, "Unreachable");
            break;
        case ICMP_TIME_EXCEEDED:
            sprintf(icmp_type_str, "Time Exceeded");
            break;
        default:
            sprintf(icmp_type_str, "Type %u", icmph->type);
            break;
    }
    
    // 计算载荷长度
    payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - sizeof(struct icmphdr);
    
    // 输出日志
    printk(KERN_INFO "%s [RULE_ID:%u] %s ICMP %s > %s type=%s code=%u id=%u seq=%u length %u\n",
           timestamp,
           rule_id,
           action,
           src_ip, dst_ip,
           icmp_type_str, icmph->code,
           ntohs(icmph->un.echo.id),
           ntohs(icmph->un.echo.sequence),
           payload_len);
}

/**
 * 主规则匹配日志记录函数
 */
void log_rule_match(uint32_t rule_id, 
                    struct rule_list_node* rule_node,
                    struct sk_buff* skb,
                    const char* action) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;
    struct icmphdr* icmph;
    char timestamp[32];
    
    if (!skb || !rule_node || !action)
        return;
    
    // 获取 IP 头
    iph = ip_hdr(skb);
    if (!iph)
        return;
    
    // 根据协议类型处理
    switch (iph->protocol) {
        case IPPROTO_TCP: {
            tcph = tcp_hdr(skb);
            if (tcph)
                log_rule_match_tcp_packet(rule_id, iph, tcph, action);
            break;
        }
        
        case IPPROTO_UDP: {
            udph = udp_hdr(skb);
            if (udph)
                log_rule_match_udp_packet(rule_id, iph, udph, action);
            break;
        }
        
        case IPPROTO_ICMP: {
            icmph = icmp_hdr(skb);
            if (icmph)
                log_rule_match_icmp_packet(rule_id, iph, icmph, action);
            break;
        }
        
        default: {
            // 记录其他协议类型
            char src_ip[16], dst_ip[16];
            get_rule_match_timestamp(timestamp, sizeof(timestamp));
            ip_to_string(iph->saddr, src_ip);
            ip_to_string(iph->daddr, dst_ip);
            printk(KERN_INFO "%s [RULE_ID:%u] %s Protocol %u %s > %s\n",
                   timestamp,
                   rule_id,
                   action,
                   iph->protocol,
                   src_ip,
                   dst_ip);
            break;
        }
    }
}
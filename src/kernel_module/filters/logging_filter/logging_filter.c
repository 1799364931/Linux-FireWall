#include "logging_filter.h"
#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <net/ip.h>

/**
 * 获取当前系统时间戳（联网时间）
 * 返回格式: "HH:MM:SS.ffffff"
 */
void get_current_timestamp(char* timestamp_buf, size_t buf_size) {
    struct timespec64 ts;
    struct tm tm;
    unsigned long local_time;

    // 获取当前时间（包含纳秒精度）
    ktime_get_real_ts64(&ts);

    // 转换为本地时间
    local_time = (unsigned long)(ts.tv_sec - (sys_tz.tz_minuteswest * 60));
    time64_to_tm(local_time, 0, &tm);

    // 格式化时间戳：HH:MM:SS.ffffff
    snprintf(timestamp_buf, buf_size, "%02d:%02d:%02d.%06ld", tm.tm_hour,
             tm.tm_min, tm.tm_sec,
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
 * 例如: "SYN,ACK" 或 "FIN,ACK" 或 "P."
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

/**
 * 记录 TCP 数据包信息
 */
static inline void log_tcp_packet(struct iphdr* iph, struct tcphdr* tcph) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    char flags_str[64];
    uint32_t seq, ack;
    uint16_t src_port, dst_port;
    uint16_t payload_len;

    // 获取时间戳
    get_current_timestamp(timestamp, sizeof(timestamp));

    // 转换 IP 地址
    ip_to_string(iph->saddr, src_ip);
    ip_to_string(iph->daddr, dst_ip);

    // 转换端口号（网络字节序转本地字节序）
    src_port = ntohs(tcph->source);
    dst_port = ntohs(tcph->dest);

    // 获取序列号和确认号
    seq = ntohl(tcph->seq);
    ack = ntohl(tcph->ack_seq);

    // 获取 TCP 标志位
    get_tcp_flags_string(tcph->fin | (tcph->syn << 1) | (tcph->rst << 2) |
                             (tcph->psh << 3) | (tcph->ack << 4),
                         flags_str);

    // 计算载荷长度
    payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);

    // 输出日志
    // printk(KERN_INFO "%s TCP %s.%u > %s.%u Flags[%s] seq %u ack %u win %u
    // length %u\n",
    //        timestamp,
    //        src_ip, src_port,
    //        dst_ip, dst_port,
    //        flags_str,
    //        seq, ack,
    //        ntohs(tcph->window),
    //        payload_len);

    char* reply_msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);

    sprintf(reply_msg,
            "%s TCP %s.%u > %s.%u Flags[%s] seq %u ack %u win %u length %u\n",
            timestamp, src_ip, src_port, dst_ip, dst_port, flags_str, seq, ack,
            ntohs(tcph->window), payload_len);

    notify_user_event(reply_msg, LOG_BUFFER_SIZE, user_portid,
                      CMD_LOGGING_FETCH, ATTR_LOG);

    kfree(reply_msg);
}

/**
 * 记录 UDP 数据包信息
 */
static inline void log_udp_packet(struct iphdr* iph, struct udphdr* udph) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    uint16_t src_port, dst_port;
    uint16_t payload_len;

    // 获取时间戳
    get_current_timestamp(timestamp, sizeof(timestamp));

    // 转换 IP 地址
    ip_to_string(iph->saddr, src_ip);
    ip_to_string(iph->daddr, dst_ip);

    // 转换端口号
    src_port = ntohs(udph->source);
    dst_port = ntohs(udph->dest);

    // UDP 长度包含头部，所以载荷 = UDP 总长度 - 8（UDP 头部大小）
    payload_len = ntohs(udph->len) - sizeof(struct udphdr);

    // 输出日志
    // printk(KERN_INFO "%s UDP %s.%u > %s.%u length %u\n", timestamp, src_ip,
    //        src_port, dst_ip, dst_port, ntohs(udph->len));

    char* reply_msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);

    sprintf(reply_msg, "%s UDP %s.%u > %s.%u length %u\n", timestamp, src_ip,
            src_port, dst_ip, dst_port, ntohs(udph->len));

    notify_user_event(reply_msg, LOG_BUFFER_SIZE, user_portid,
                      CMD_LOGGING_FETCH, ATTR_LOG);

    kfree(reply_msg);
}

/**
 * 记录 ICMP 数据包信息
 */
static inline void log_icmp_packet(struct iphdr* iph, struct icmphdr* icmph) {
    char src_ip[16], dst_ip[16];
    char timestamp[32];
    char icmp_type_str[32];
    uint16_t payload_len;

    // 获取时间戳
    get_current_timestamp(timestamp, sizeof(timestamp));

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
    payload_len =
        ntohs(iph->tot_len) - (iph->ihl << 2) - sizeof(struct icmphdr);

    // 输出日志
    // printk(KERN_INFO "%s ICMP %s > %s type=%s code=%u id=%u seq=%u length
    // %u\n",
    //        timestamp, src_ip, dst_ip, icmp_type_str, icmph->code,
    //        ntohs(icmph->un.echo.id), ntohs(icmph->un.echo.sequence),
    //        payload_len);

    char* reply_msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);

    sprintf(
        reply_msg, "%s ICMP %s > %s type=%s code=%u id=%u seq=%u length %u\n",
        timestamp, src_ip, dst_ip, icmp_type_str, icmph->code,
        ntohs(icmph->un.echo.id), ntohs(icmph->un.echo.sequence), payload_len);

    notify_user_event(reply_msg, LOG_BUFFER_SIZE, user_portid,
                      CMD_LOGGING_FETCH, ATTR_LOG);

    kfree(reply_msg);
}

/**
 * 记录 ARP 数据包信息
 */
static inline void log_arp_packet(struct sk_buff* skb) {
    struct arphdr* arph;
    struct arp_payload {
        unsigned char sha[ETH_ALEN];
        __be32 spa;
        unsigned char tha[ETH_ALEN];
        __be32 tpa;
    }* arp_payload;

    char timestamp[32];
    char src_ip[16], dst_ip[16];
    char op_str[16];

    arph = arp_hdr(skb);
    if (!arph)
        return;

    // 只处理 IPv4 over Ethernet ARP
    if (arph->ar_hrd != htons(ARPHRD_ETHER) || arph->ar_pro != htons(ETH_P_IP))
        return;

    arp_payload = (struct arp_payload*)(arph + 1);

    // 获取时间戳
    get_current_timestamp(timestamp, sizeof(timestamp));

    // 转换 IP 地址
    ip_to_string(arp_payload->spa, src_ip);
    ip_to_string(arp_payload->tpa, dst_ip);

    // 获取 ARP 操作类型
    switch (ntohs(arph->ar_op)) {
        case ARPOP_REQUEST:
            sprintf(op_str, "Request");
            break;
        case ARPOP_REPLY:
            sprintf(op_str, "Reply");
            break;
        default:
            sprintf(op_str, "Op %u", ntohs(arph->ar_op));
            break;
    }

    // 输出日志
    // printk(KERN_INFO "%s ARP %s > %s %s (hwtype=%u)\n", timestamp, src_ip,
    //        dst_ip, op_str, ntohs(arph->ar_hrd));

    char* reply_msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);

    sprintf(reply_msg, "%s ARP %s > %s %s (hwtype=%u)\n", timestamp, src_ip,
            dst_ip, op_str, ntohs(arph->ar_hrd));

    notify_user_event(reply_msg, LOG_BUFFER_SIZE, user_portid,
                      CMD_LOGGING_FETCH, ATTR_LOG);

    kfree(reply_msg);
}

/**
 * 主日志记录 Hook 函数
 * 记录所有通过的数据包
 */
unsigned int logging_hook(void* priv,
                          struct sk_buff* skb,
                          const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;
    struct icmphdr* icmph;
    char timestamp[32];

    if (!skb)
        return NF_ACCEPT;

    // 获取 IP 头
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // 根据协议类型处理
    switch (iph->protocol) {
        case IPPROTO_TCP: {
            tcph = tcp_hdr(skb);
            if (tcph)
                log_tcp_packet(iph, tcph);
            break;
        }

        case IPPROTO_UDP: {
            udph = udp_hdr(skb);
            if (udph)
                log_udp_packet(iph, udph);
            break;
        }

        case IPPROTO_ICMP: {
            icmph = icmp_hdr(skb);
            if (icmph)
                log_icmp_packet(iph, icmph);
            break;
        }

        default:
            // 记录其他协议类型
            get_current_timestamp(timestamp, sizeof(timestamp));
            // printk(KERN_INFO "%s Protocol %u (other)\n", timestamp,
            //        iph->protocol);

            char* reply_msg = kmalloc(LOG_BUFFER_SIZE, GFP_KERNEL);

            sprintf(reply_msg, "%s Protocol %u (other)\n", timestamp,
                    iph->protocol);

            notify_user_event(reply_msg, LOG_BUFFER_SIZE, user_portid,
                              CMD_LOGGING_FETCH, ATTR_LOG);

            kfree(reply_msg);
            break;
    }

    // ARP 处理（需要检查 skb->protocol）
    if (skb->protocol == htons(ETH_P_ARP)) {
        log_arp_packet(skb);
    }

    return NF_ACCEPT;
}
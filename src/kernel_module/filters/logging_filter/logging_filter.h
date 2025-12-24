#ifndef _LOGGING_FILTER_H
#define _LOGGING_FILTER_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include "../../rule/rule.h"
#include "../../communicate/netlink_module/netlink_module.h"

// 定义日志记录的最大长度
#define LOG_BUFFER_SIZE 512

// TCP 标志位标记
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08

/**
 * 日志记录 hook 函数
 * 记录所有通过的数据包信息
 */
unsigned int logging_hook(void* priv,
                          struct sk_buff* skb,
                          const struct nf_hook_state* state);

/**
 * 获取当前系统时间戳
 * 返回格式: "HH:MM:SS.ffffff"
 */
void get_current_timestamp(char* timestamp_buf, size_t buf_size);

/**
 * 解析和记录 TCP 数据包
 */
// static inline void log_tcp_packet(struct iphdr* iph, struct tcphdr* tcph);

// /**
//  * 解析和记录 UDP 数据包
//  */
// static inline void log_udp_packet(struct iphdr* iph, struct udphdr* udph);

// /**
//  * 解析和记录 ICMP 数据包
//  */
// static inline void log_icmp_packet(struct iphdr* iph, struct icmphdr* icmph);

// /**
//  * 解析和记录 ARP 数据包
//  */
// static inline void log_arp_packet(struct sk_buff* skb);

// /**
//  * 将 IP 地址转换为点分十进制字符串
//  */
// static inline void ip_to_string(uint32_t ip, char* str);

// /**
//  * 获取 TCP 标志位的字符串表示
//  */
// static inline void get_tcp_flags_string(uint8_t flags, char* flags_str);

#endif /* _LOGGING_FILTER_H */
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// 定义模块信息
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple Firewall Module - Drop ICMP Requests");
MODULE_VERSION("1.0");

// Netfilter钩子函数声明
static unsigned int icmp_drop_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

// 定义netfilter钩子操作结构
static struct nf_hook_ops nfho = {
    .hook = icmp_drop_hook,          // 钩子函数
    .pf = PF_INET,                   // 协议族：IPv4
    .hooknum = NF_INET_PRE_ROUTING,  // 钩子点：在路由之前
    .priority = NF_IP_PRI_FIRST,     // 优先级：最高
};

// ICMP丢弃钩子函数实现
static unsigned int icmp_drop_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct icmphdr* icmph;

    // 检查sk_buff是否有效
    if (!skb)
        return NF_ACCEPT;

    // 获取IP头
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // 检查是否为ICMP协议
    if (iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    // 获取ICMP头
    icmph = icmp_hdr(skb);
    if (!icmph)
        return NF_ACCEPT;

    // 检查是否为ICMP请求（类型为8）
    if (icmph->type == ICMP_ECHO) {
        printk(KERN_INFO "Firewall: Dropping ICMP request from %pI4\n",
               &iph->saddr);
        return NF_DROP;  // 丢弃数据包
    }

    // 接受其他所有数据包
    return NF_ACCEPT;
}

// 模块初始化函数
static int __init firewall_init(void) {
    int ret;

    printk(KERN_INFO "Firewall module: Initializing...\n");

    // 注册netfilter钩子
    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        printk(KERN_ERR "Firewall module: Failed to register netfilter hook\n");
        return ret;
    }

    printk(KERN_INFO
           "Firewall module: Successfully loaded - ICMP requests will be "
           "dropped\n");
    return 0;
}

// 模块退出函数
static void __exit firewall_exit(void) {
    // 注销netfilter钩子
    nf_unregister_net_hook(&init_net, &nfho);

    printk(
        KERN_INFO
        "Firewall module: Unloaded - ICMP requests will be accepted again\n");
}

// 注册模块的初始化和退出函数
module_init(firewall_init);
module_exit(firewall_exit);
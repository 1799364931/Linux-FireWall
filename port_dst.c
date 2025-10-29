#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Simple Firewall Module - IP Filter");
MODULE_VERSION("1.0");

static unsigned int port_dst_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state);

static struct nf_hook_ops nfho = {
    .hook = port_dst_filter_hook,          // 钩子函数
    .pf = PF_INET,                   // 协议族：IPv4
    .hooknum = NF_INET_PRE_ROUTING,  // 钩子点：在路由之前
    .priority = NF_IP_PRI_FIRST,     // 优先级：最高
};


uint16_t port = 22;

static unsigned int port_dst_filter_hook(void* priv,
                                   struct sk_buff* skb,
                                   const struct nf_hook_state* state) {
    struct iphdr* iph;
    struct tcphdr* tcph;
    struct udphdr* udph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    if(tcph && port == ntohs(tcph->dest)){
        return NF_DROP;
    }

    udph = udp_hdr(skb);
    if(udph && port == ntohs(udph->dest)){
        return NF_DROP;
    }
    

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
           "Firewall module: Successfully loaded - IP filter\n");
    return 0;
}

// 模块退出函数
static void __exit firewall_exit(void) {
    // 注销netfilter钩子
    nf_unregister_net_hook(&init_net, &nfho);

    printk(
        KERN_INFO
        "Firewall module: Unloaded - IP filter exit\n");
}

// 注册模块的初始化和退出函数
module_init(firewall_init);
module_exit(firewall_exit);
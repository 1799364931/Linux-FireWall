/*
    firewall启动
*/

#include "ip_filter/ip_filter.h"
#include "mac_filter/mac_filter.h"
#include "port_filter/port_filter.h"
#include "protocol_filter/protocol.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Simple Firewall Module");
MODULE_VERSION("1.0");

bool check(int ret) {
    if (ret < 0) {
        printk(KERN_ERR "Firewall module: Failed to register netfilter hook\n");
        return ret;
    }
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
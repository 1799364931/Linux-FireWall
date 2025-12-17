
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "communicate/netlink_module/netlink_module.h"
#include "filters/content_filter/content_filter.h"
#include "filters/interface_filter/interface_filter.h"
#include "filters/ip_filter/ip_filter.h"
#include "filters/mac_filter/mac_filter.h"
#include "filters/port_filter/port_filter.h"
#include "filters/protocol_filter/protocol.h"
#include "filters/state_filter/state_filter.h"
#include "filters/time_filter/time_filter.h"
#include "rule/rule.h"
#include "filters/logging_filter/logging_filter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Simple Firewall Module");
MODULE_VERSION("1.0");

static struct nf_hook_ops hook_ops_array[] = {
    // 最先流入的HOOK
    {
        .hook = ip_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = mac_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_LAST,
    },
    {
        .hook = ipv4_protocol_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_RAW_BEFORE_DEFRAG,
    },
    {
        .hook = port_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_DEFRAG,
    },
    {
        .hook = content_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_DEFRAG,
    },
    {
        .hook = time_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_DEFRAG,
    },
    {
        .hook = state_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_DEFRAG,
    },
    // 最后流入的HOOK
    {
        .hook = interface_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_LAST,
    },
          // 在 LOCAL_IN
    {
        .hook = logging_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_LAST ,  // 最后执行，在最后的规则检查之后
    },

};

static int __init firewall_init(void) {
    int ret;
    printk(KERN_INFO "Firewall module: Initializing...\n");
    // 注册netfilter钩子
    for (uint32_t i = 0;
         i < (sizeof(hook_ops_array) / sizeof(struct nf_hook_ops)); i++) {
        ret = nf_register_net_hook(&init_net, &hook_ops_array[i]);
        if (ret < 0) {
            printk(KERN_ERR
                   "Firewall module: Failed to register netfilter hook\n");
            return ret;
        }
    }
    ret = genl_register_family(&my_family);
    if (ret)
        pr_err("failed to register genl family: %d\n", ret);

    printk(KERN_INFO "Firewall module: Successfully loaded\n");
    return 0;
}

// 模块退出函数
static void __exit firewall_exit(void) {
    // 注销netfilter钩子
    for (uint32_t i = 0;
         i < (sizeof(hook_ops_array) / sizeof(struct nf_hook_ops)); i++) {
        nf_unregister_net_hook(&init_net, &hook_ops_array[i]);
    }
    genl_unregister_family(&my_family);
    mutex_lock(&black_list_lock);
    release_rule_list(get_rule_list(RULE_LIST_BLACK));
    mutex_unlock(&black_list_lock);

    mutex_lock(&white_list_lock);
    release_rule_list(get_rule_list(RULE_LIST_WHITE));
    mutex_unlock(&white_list_lock);
    printk(KERN_INFO "Firewall module: Unloaded\n");
}

// 注册模块的初始化和退出函数
module_init(firewall_init);
module_exit(firewall_exit);

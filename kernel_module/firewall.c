
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "filters/content_filter/content_filter.h"
#include "filters/interface_filter/interface_filter.h"
#include "filters/ip_filter/ip_filter.h"
#include "filters/mac_filter/mac_filter.h"
#include "filters/port_filter/port_filter.h"
#include "filters/protocol_filter/protocol.h"
#include "filters/state_filter/state_filter.h"
#include "filters/time_filter/time_filter.h"
#include "rule/rule.h"
#include "rule/rule_bitmap.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Simple Firewall Module");
MODULE_VERSION("1.0");

static struct nf_hook_ops hook_ops_array[] = {
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
    {
        .hook = interface_filter_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_CONNTRACK_DEFRAG,
    }

};

static int __init firewall_init(void) {
    int ret;

    // 初始化规则链表

    // ip:192.168.119.134 port:22 protocol = tcp
    struct match_condition match_conditions[3];
    match_conditions[0].src_ip = in_aton("192.168.119.134");
    match_conditions[0].match_type = RULE_SRC_IP;
    match_conditions[1].dst_port = htons(22);
    match_conditions[1].match_type = RULE_DST_PORT;
    match_conditions[2].ipv4_protocol = IPPROTO_TCP;
    match_conditions[2].match_type = RULE_IPV4_PROTOCOL;

    struct rule_list_node* new_rule_list_node = (struct rule_list_node*)kmalloc(
        sizeof(struct rule_list_node), GFP_KERNEL);
    new_rule_list_node->conditions = match_conditions;
    new_rule_list_node->condition_count = 3;
    new_rule_list_node->rule_bitmap = compute_bitmap(
        new_rule_list_node->condition_count, new_rule_list_node->conditions);

    add_black_list_rule(new_rule_list_node);

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
    printk(KERN_INFO "Firewall module: Unloaded\n");
}

// 注册模块的初始化和退出函数
module_init(firewall_init);
module_exit(firewall_exit);

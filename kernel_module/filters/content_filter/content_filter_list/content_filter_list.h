# ifndef _CONTENT_FILTER_LIST_H
# define _CONTENT_FILTER_LIST_H
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>

// 内容过滤规则结构（支持多条字符串匹配规则）
struct content_rule {
    char *target_str;        // 要匹配的目标字符串（如"malicious"）
    unsigned int str_len;    // 目标字符串长度
    struct list_head list;   // 链表节点
};

// 内容规则链表（全局管理）
struct content_rule_list {
    struct list_head head;
    int count;
};

// 函数声明
int init_content_rules(struct content_rule_list* content_list);                  // 初始化内容规则
void cleanup_content_rules(struct content_rule_list* content_list);              // 清理内容规则
int add_content_rule(const char *target_str,struct content_rule_list* content_list);  // 添加内容匹配规则

#endif
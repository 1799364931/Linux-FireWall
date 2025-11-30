#include "content_filter_list.h"

/**
 * 初始化内容规则链表
 */

// static struct content_rule_list global_content_list;

int init_content_rules(struct content_rule_list* content_list) {
    INIT_LIST_HEAD(&content_list->head);
    content_list->count = 0;
    printk(KERN_INFO "ContentWall: Content rules initialized\n");
    return 0;
}

/**
 * 清理内容规则（释放内存）
 */
void cleanup_content_rules(struct content_rule_list* content_list) {
    struct content_rule *rule, *tmp;

    list_for_each_entry_safe(rule, tmp, &content_list->head, list) {
        list_del(&rule->list);
        kfree(rule->target_str);
        kfree(rule)
    }

    content_list->count = 0;
    printk(KERN_INFO "ContentWall: Content rules cleaned up\n");
}

/**
 * 添加内容匹配规则（目标字符串）
 */
int add_content_rule(const char* target_str,
                     struct content_rule_list* content_list) {
    struct content_rule* new_rule;
    unsigned int str_len;

    // 参数验证
    if (!target_str || (str_len = strlen(target_str)) == 0) {
        printk(KERN_WARNING "ContentWall: Invalid target string\n");
        return -EINVAL;
    }

    // 分配规则结构体内存
    new_rule = kmalloc(sizeof(struct content_rule), GFP_KERNEL);
    if (!new_rule) {
        printk(KERN_ERR "ContentWall: Failed to allocate rule memory\n");
        return -ENOMEM;
    }

    // 分配字符串内存（内核中不能直接用用户态字符串指针，需拷贝）
    new_rule->target_str =
        kmalloc(str_len + 1, GFP_KERNEL);  // +1 存字符串结束符'\0'
    if (!new_rule->target_str) {
        printk(KERN_ERR "ContentWall: Failed to allocate string memory\n");
        kfree(new_rule);
        return -ENOMEM;
    }

    // 拷贝目标字符串
    strncpy(new_rule->target_str, target_str, str_len);
    new_rule->target_str[str_len] = '\0';  // 手动添加结束符
    new_rule->str_len = str_len;

    // 添加到规则链表
    list_add_tail(&new_rule->list, &content_list->head);
    content_list->count++;

    printk(KERN_INFO "ContentWall: Added content rule - target: %s\n",
           target_str);
    return 0;
}

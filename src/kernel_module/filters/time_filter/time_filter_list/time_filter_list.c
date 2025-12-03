#include "time_filter_list.h"

/**
 * init_time_rules - 初始化时间规则系统
 */
int init_time_rules(struct time_rule_list* time_list) {
    INIT_LIST_HEAD(&time_list->head);
    time_list->count = 0;

    printk(KERN_INFO "TimeWall: Time rules initialized\n");
    return 0;
}

/**
 * cleanup_time_rules - 清理时间规则系统
 */
void cleanup_time_rules(struct time_rule_list* time_list) {
    struct time_rule *rule, *tmp;

    list_for_each_entry_safe(rule, tmp, &time_list->head, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    time_list->count = 0;
    printk(KERN_INFO "TimeWall: Time rules cleaned up\n");
}

/**
 * add_time_rule - 添加时间规则
 */
int add_time_rule(int start_hour,
                  int start_min,
                  int end_hour,
                  int end_min,
                  struct time_rule_list* time_list) {
    struct time_rule* new_rule;
    /* 参数验证 */
    if (start_hour < 0 || start_hour > 23 || end_hour < 0 || end_hour > 23 ||
        start_min < 0 || start_min > 59 || end_min < 0 || end_min > 59) {
        printk(KERN_WARNING "TimeWall: Invalid time parameters\n");
        return -EINVAL;
    }

    /* 分配内存 */
    new_rule = kmalloc(sizeof(struct time_rule), GFP_KERNEL);
    if (!new_rule) {
        printk(KERN_ERR "TimeWall: Failed to allocate memory for rule\n");
        return -ENOMEM;
    }

    /* 填充规则 */
    new_rule->start_hour = start_hour;
    new_rule->start_min = start_min;
    new_rule->end_hour = end_hour;
    new_rule->end_min = end_min;

    /* 添加到链表 */
    list_add_tail(&new_rule->list, &time_list->head);
    printk(KERN_INFO "%d:%d %d:%d", start_hour, start_min, end_hour, end_min);

    time_list->count++;

    printk(KERN_INFO "TimeWall: Added rule - %02d:%02d-%02d:%02d\n", start_hour,
           start_min, end_hour, end_min);

    return 0;
}

/**
 * delete_all_time_rules - 删除所有时间规则
 */
void delete_all_time_rules(struct time_rule_list* time_list) {
    struct time_rule *rule, *tmp;
    int deleted = 0;

    list_for_each_entry_safe(rule, tmp, &time_list->head, list) {
        list_del(&rule->list);
        kfree(rule);
        deleted++;
    }

    time_list->count = 0;
    printk(KERN_INFO "TimeWall: Deleted %d rules\n", deleted);
}
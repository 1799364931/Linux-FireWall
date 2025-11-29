#include "rule.h"

struct rule_list* black_list_singleton = NULL;
struct rule_list* white_list_singleton = NULL;

uint64_t compute_bitmap(uint32_t size, struct match_condition* conditions) {
    uint64_t bitmap = 0;
    for (uint32_t i = 0; i < size; i++) {
        bitmap |= conditions[i].match_type;
    }
    return bitmap;
}

struct rule_list* get_rule_list(enum rule_list_type type) {
    struct rule_list** target;

    if (type == RULE_LIST_BLACK) {
        target = &black_list_singleton;
    } else {
        target = &white_list_singleton;
    }

    if (*target == NULL) {
        *target = kzalloc(sizeof(struct rule_list), GFP_KERNEL);
        if (!*target)
            return NULL;

        (*target)->type = type;
        INIT_LIST_HEAD(&(*target)->nodes);
    }

    return *target;
}

void release_rule_list(struct rule_list* list) {
    struct rule_list_node *pos, *n;
    list_for_each_entry_safe(pos, n, &list->nodes, list) {
        // todo 释放内存
        // pos -> match_type -> contents?

        for (uint32_t i = 0; i < pos->condition_count; i++) {
            switch (pos->conditions[i].match_type) {
                case RULE_INTERFACE: {
                    free(pos->conditions[i].interface);
                    pos->conditions[i].interface = NULL;
                    break;
                }
                case RULE_CONTENT: {
                    cleanup_content_rules(pos->conditions[i].content_list);
                    break;
                }
                case RULE_TIME_ACCEPT: {
                    cleanup_time_rules(pos->conditions[i].time_list);
                    break;
                }
                case RULE_TIME_DROP: {
                    cleanup_time_rules(pos->conditions[i].time_list);
                    break;
                }
            }
        }
        list_del(&pos->list);
        kfree(pos);
    }
}
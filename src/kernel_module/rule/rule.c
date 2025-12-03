#include "rule.h"

struct rule_list* black_list_singleton = NULL;
struct rule_list* white_list_singleton = NULL;
bool BLACK_LIST_ENABLE = true;
struct mutex black_list_lock;
struct mutex white_list_lock;
struct mutex rule_id_lock;
uint32_t rule_id = 0;

DEFINE_MUTEX(rule_id_lock);
DEFINE_MUTEX(black_list_lock);
DEFINE_MUTEX(white_list_lock);

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
        (*target)->rule_count = 0;
        INIT_LIST_HEAD(&(*target)->nodes);
    }

    return *target;
}

void release_rule_list(struct rule_list* rule_list) {
    struct rule_list_node *pos, *n;
    list_for_each_entry_safe(pos, n, &rule_list->nodes, list) {
        // todo 释放内存
        list_del(&pos->list);
        // pos -> match_type -> contents?
        release_rule(pos);
        kfree(pos);
    }
    kfree(rule_list);
}

bool del_rule(uint32_t del_rule_id, struct rule_list* rule_list) {
    struct rule_list_node *pos, *n;
    bool is_delete = false;
    list_for_each_entry_safe(pos, n, &rule_list->nodes, list) {
        if (pos->rule_id == del_rule_id) {
            list_del(&pos->list);
            release_rule(pos);
            kfree(pos);
            is_delete = true;
        }
    }
    return is_delete;
}

void release_rule(struct rule_list_node* rule) {
    for (uint32_t i = 0; i < rule->condition_count; i++) {
        switch (rule->conditions[i].match_type) {
            case RULE_INTERFACE: {
                kfree(rule->conditions[i].interface);
                rule->conditions[i].interface = NULL;
                break;
            }
            case RULE_CONTENT: {
                cleanup_content_rules(rule->conditions[i].content_list);
                break;
            }
            case RULE_TIME_ACCEPT: {
                cleanup_time_rules(rule->conditions[i].time_list);
                break;
            }
            case RULE_TIME_DROP: {
                cleanup_time_rules(rule->conditions[i].time_list);
                break;
            }
        }
    }
}

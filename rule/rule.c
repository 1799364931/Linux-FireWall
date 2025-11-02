#include "rule.h"

struct black_list* get_black_list(void) {
    static struct black_list black_list;
    static bool initialized = false;

    if (!initialized) {
        black_list.head = kmalloc(sizeof(struct rule_list_node*), GFP_KERNEL);
        if (!black_list.head)
            return NULL;

        *(black_list.head) = kmalloc(sizeof(struct rule_list_node), GFP_KERNEL);
        if (!*(black_list.head))
            return NULL;

        memset(*(black_list.head), 0, sizeof(struct rule_list_node));
        initialized = true;
    }

    return &black_list;
}

struct white_list* get_white_list(void) {
    static struct white_list white_list;
    static bool initialized = false;

    if (!initialized) {
        white_list.head = kmalloc(sizeof(struct rule_list_node*), GFP_KERNEL);
        if (!white_list.head)
            return NULL;

        *(white_list.head) = kmalloc(sizeof(struct rule_list_node), GFP_KERNEL);
        if (!*(white_list.head))
            return NULL;

        memset(*(white_list.head), 0, sizeof(struct rule_list_node));
        initialized = true;
    }

    return &white_list;
}

uint64_t compute_bitmap(uint32_t size,
                        struct match_condition* match_conditions) {
    uint64_t bitmap = 0;
    for (uint32_t i = 0; i < size; i++) {
        bitmap |= match_conditions[i].match_type;
    }
    return bitmap;
}

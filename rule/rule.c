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

void add_black_list_rule(struct rule_list_node* new_rule_list_node) {
    struct black_list* black_list = get_black_list();
    // 头节点添加
    struct rule_list_node* head = *(black_list->head);
    if (head->next == NULL) {
        head->next = new_rule_list_node;
        new_rule_list_node->priv = head;
    } else {
        struct rule_list_node* tmp = head->next;
        head->next = new_rule_list_node;
        new_rule_list_node->priv = head;
        new_rule_list_node->next = tmp;
        if (tmp) {
            tmp->priv = new_rule_list_node;
        }
    }
}

void relase_black_list(void){
    
    struct black_list* black_list = get_black_list();
    struct rule_list_node* cur = *(black_list->head);
    struct rule_list_node* next;

    while (cur) {
        next = cur->next;
        if (cur->rules) {
            kfree(cur->rules);
        }
        kfree(cur);
        cur = next;
    }

    kfree(black_list->head);
    black_list->head = NULL;
}

uint64_t compute_bitmap(uint32_t size,
                        struct match_condition* match_conditions) {
    uint64_t bitmap = 0;
    for (uint32_t i = 0; i < size; i++) {
        bitmap |= match_conditions[i].match_type;
    }
    return bitmap;
}

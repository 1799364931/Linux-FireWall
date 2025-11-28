
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "../../public_structs/match_condition_msg.h"
#include "../../public_structs/rule_bitmap.h"
#include "../rule/rule.h"
// 构造一个rule_list_node的数据结构

static inline uint32_t read_u32(char* base, uint32_t offset) {
    return *(uint32_t*)(base + offset);
}

void parse_buffer(char* msg_buffer_start_ptr) {
    struct rule_list_node* node =
        kmalloc(sizeof(struct rule_list_node), GFP_KERNEL);
    INIT_LIST_HEAD(&node->list);
    // 重构buffer
    struct rule_entry_msg* entry = msg_buffer_start_ptr;
    uint32_t rule_entry_msg_size =
        sizeof(struct rule_entry_msg) +
        entry->condition_count * sizeof(struct match_condition_msg);
    char* buffer_data_ptr = (char*)entry + rule_entry_msg_size;

    // 内核规则链表节点开辟空间
    node->conditions = kmalloc(
        entry->condition_count * sizeof(struct match_condition), GFP_KERNEL);

    node->condition_count = entry->condition_count;
    node->rule_bitmap = entry->bitmap;

    size_t union_size = sizeof(struct match_condition) -
                        offsetof(struct match_condition, src_ip);

    for (uint32_t i = 0; i < entry->condition_count; i++) {
        // 排除需要额外读取buffer的情况
        node->conditions[i].match_type = entry->conditions[i].match_type;
        switch (node->conditions[i].match_type) {
            case RULE_CONTENT: {
                uint32_t strs_cnt = read_u32(
                    buffer_data_ptr, entry->conditions[i].buffer_offset);
                struct content_rule_list* content_list =
                    kmalloc(sizeof(struct content_rule_list), GFP_KERNEL);

                node->conditions[i].content_list = content_list;
                content_list->count = strs_cnt;
                INIT_LIST_HEAD(&content_list->head);

                // 一次性分配所有 content_rule
                struct content_rule* rules = kmalloc_array(
                    strs_cnt, sizeof(struct content_rule), GFP_KERNEL);

                char* buffer_data_mov_ptr =
                    buffer_data_ptr + entry->conditions[i].buffer_offset + 1;

                for (uint32_t j = 0; j < strs_cnt; j++) {
                    uint32_t str_len = *buffer_data_mov_ptr;
                    buffer_data_mov_ptr += sizeof(uint32_t);

                    rules[j].str_len = str_len;
                    rules[j].target_str = kmalloc(str_len + 1, GFP_KERNEL);

                    memcpy(rules[j].target_str, buffer_data_mov_ptr, str_len);
                    rules[j].target_str[str_len] = '\0';

                    buffer_data_mov_ptr += str_len;

                    // 把数组元素挂到链表
                    INIT_LIST_HEAD(&rules[j].list);
                    list_add_tail(&rules[j].list, &content_list->head);
                }

                break;
            }
            case RULE_INTERFACE: {
                uint32_t str_len = read_u32(buffer_data_ptr,
                                            entry->conditions[i].buffer_offset);
                node->conditions[i].interface =
                    kmalloc(str_len + 1, GFP_KERNEL);
                memcpy(node->conditions[i].interface,
                       buffer_data_ptr + entry->conditions[i].buffer_offset + 1,
                       str_len);
                node->conditions[i].interface[str_len] = '\0';
                printk(KERN_INFO "interface is %s",node->conditions[i].interface[str_len]);
                break;
            }
            case RULE_TIME_ACCEPT: {
                // [时间对个数] [HH:MM][HH:MM] 一个时间2*4 = 8字节
                struct time_rule_list* time_list =
                    kmalloc(sizeof(struct time_rule_list), GFP_KERNEL);
                uint32_t time_pair_cnt = read_u32(
                    buffer_data_ptr, entry->conditions[i].buffer_offset);
                time_list->count = time_pair_cnt;
                node->conditions[i].time_list = time_list;

                int* buffer_data_mov_ptr =
                    buffer_data_ptr + entry->conditions[i].buffer_offset + 1;

                for (uint32_t j = 0; j < time_pair_cnt; j++) {
                    int* time_pair_pos_start =
                        buffer_data_mov_ptr + j * 4 * sizeof(int);
                    add_time_rule(*time_pair_pos_start,
                                  *(time_pair_pos_start + 1),
                                  *(time_pair_pos_start + 2),
                                  *(time_pair_pos_start + 3), time_list);
                }

                break;
            }
            case RULE_TIME_DROP: {
                break;
            }
            default: {
                memcpy(&node->conditions[i].src_ip, &node->conditions[i].src_ip,
                       union_size);
            }
        }
    }

    //黑名单
    add_list(node,&get_rule_list(RULE_LIST_BLACK)->nodes);
};
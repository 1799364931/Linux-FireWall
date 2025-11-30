
#include "buffer_parse.h"

static inline uint32_t read_u32(char* base, uint32_t offset) {
    return *(uint32_t*)(base + offset);
}

void parse_buffer(const char* msg_buffer_start_ptr) {
    struct rule_list_node* node =
        kmalloc(sizeof(struct rule_list_node), GFP_KERNEL);
    INIT_LIST_HEAD(&node->list);
    // 重构buffer
    struct rule_entry_msg* entry = (struct rule_entry_msg*)msg_buffer_start_ptr;
    uint32_t rule_entry_msg_size =
        sizeof(struct rule_entry_msg) +
        entry->condition_count * sizeof(struct match_condition_msg);

    char* buffer_data_ptr = (char*)msg_buffer_start_ptr + rule_entry_msg_size;

    printk(KERN_INFO "rule_entry_msg size:%d,condition_count is %d \n",
           rule_entry_msg_size, entry->condition_count);
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
                //! 不能这样分配 这样分配无法使用链表来单个释放
                // struct content_rule* rules = kmalloc_array(
                //     strs_cnt, sizeof(struct content_rule), GFP_KERNEL);

                char* buffer_data_mov_ptr = buffer_data_ptr +
                                            entry->conditions[i].buffer_offset +
                                            sizeof(uint32_t);

                printk(KERN_INFO "cnts is %d", strs_cnt);

                for (uint32_t j = 0; j < strs_cnt; j++) {
                    printk(KERN_INFO "test!");
                    struct content_rule* rule =
                        kmalloc(sizeof(*rule), GFP_KERNEL);
                    uint32_t str_len = *buffer_data_mov_ptr;
                    buffer_data_mov_ptr += sizeof(uint32_t);

                    rule->str_len = str_len;
                    rule->target_str =
                        kmalloc(str_len + sizeof(char), GFP_KERNEL);

                    memcpy(rule->target_str, buffer_data_mov_ptr, str_len);
                    rule->target_str[str_len] = '\0';
                    printk(KERN_INFO "curstr is %s", rule->target_str);
                    buffer_data_mov_ptr += str_len;

                    // 把数组元素挂到链表
                    INIT_LIST_HEAD(&rule->list);
                    list_add_tail(&rule->list, &content_list->head);
                }

                break;
            }
            case RULE_INTERFACE: {
                uint32_t str_len = read_u32(buffer_data_ptr,
                                            entry->conditions[i].buffer_offset);
                node->conditions[i].interface =
                    kmalloc(str_len + sizeof(char), GFP_KERNEL);
                memcpy(node->conditions[i].interface,
                       buffer_data_ptr + entry->conditions[i].buffer_offset +
                           sizeof(uint32_t),
                       str_len);
                node->conditions[i].interface[str_len] = '\0';

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
                INIT_LIST_HEAD(&time_list->head);
                int* buffer_data_mov_ptr =
                    (int*)(buffer_data_ptr +
                           entry->conditions[i].buffer_offset +
                           sizeof(uint32_t));

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
                // [时间对个数] [HH:MM][HH:MM] 一个时间2*4 = 8字节

                struct time_rule_list* time_list =
                    kmalloc(sizeof(struct time_rule_list), GFP_KERNEL);
                uint32_t time_pair_cnt = read_u32(
                    buffer_data_ptr, entry->conditions[i].buffer_offset);
                time_list->count = time_pair_cnt;
                node->conditions[i].time_list = time_list;
                INIT_LIST_HEAD(&time_list->head);
                int* buffer_data_mov_ptr =
                    (int*)(buffer_data_ptr +
                           entry->conditions[i].buffer_offset +
                           sizeof(uint32_t));

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
            default: {
                //*这里报错是没问题的，src_ip确实比union_size更小
                memcpy(&node->conditions[i].dst_mac,
                       &entry->conditions[i].dst_mac, 6);
            }
        }
    }

    // 黑名单
    list_add(&node->list, &get_rule_list(RULE_LIST_BLACK)->nodes);
};

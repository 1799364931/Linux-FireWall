
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

    mutex_lock(&rule_id_lock);
    node->rule_id = rule_id++;
    mutex_unlock(&rule_id_lock);
    // size_t union_size = sizeof(struct match_condition) -
    //                     offsetof(struct match_condition, src_ip);

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
                printk(KERN_INFO "strs_cnt:%d", strs_cnt);

                for (uint32_t j = 0; j < strs_cnt; j++) {
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

    //* 这里考虑拆分一下逻辑 不要在序列化里面做添加节点的操作
    if (node->rule_bitmap & RULE_BLACK) {
        mutex_lock(&black_list_lock);
        list_add(&node->list, &get_rule_list(RULE_LIST_BLACK)->nodes);
        get_rule_list(RULE_LIST_BLACK)->rule_count++;
        mutex_unlock(&black_list_lock);
    } else {
        mutex_lock(&white_list_lock);
        list_add(&node->list, &get_rule_list(RULE_LIST_WHITE)->nodes);
        get_rule_list(RULE_LIST_WHITE)->rule_count++;
        mutex_unlock(&white_list_lock);
    }
};

// 返回空间大小
uint32_t build_rule_list_msg(char** target_buffer_ptr,
                             enum rule_list_type type) {
    struct rule_list* list = get_rule_list(type);
    struct rule_list_node *pos, *n;
    uint32_t j = 0;
    uint32_t total_size = RULE_MSG_SIZE * list->rule_count + sizeof(uint32_t);
    *target_buffer_ptr = kzalloc(total_size, GFP_KERNEL);
    char* startptr = *target_buffer_ptr;
    if (!startptr) {
        return 0;
    }

    list_for_each_entry_safe(pos, n, &list->nodes, list) {
        char* ptr = startptr + j * RULE_MSG_SIZE + sizeof(uint32_t);
        j++;

        int written = scnprintf(ptr, RULE_MSG_SIZE, "Rule %u: ", pos->rule_id);
        for (uint32_t i = 0; i < pos->condition_count; i++) {
            switch (pos->conditions[i].match_type) {
                case RULE_SRC_IP: {
                    uint32_t t_ip = htonl(pos->conditions[i].src_ip);
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "src_ip=%pI4 ", &pos->conditions[i].src_ip);
                    break;
                }
                case RULE_SRC_IP_MASK: {
                    uint32_t t_ip = htonl(pos->conditions[i].src_mask_ip);
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "src_ip=%pI4 ", &pos->conditions[i].src_mask_ip);
                    break;
                }
                case RULE_DST_IP: {
                    uint32_t t_ip = htonl(pos->conditions[i].dst_ip);
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "src_ip=%pI4 ", &pos->conditions[i].dst_ip);
                    break;
                }
                case RULE_DST_IP_MASK: {
                    uint32_t t_ip = htonl(pos->conditions[i].dst_mask_ip);
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "src_ip=%pI4 ", &pos->conditions[i].dst_mask_ip);
                    break;
                }
                case RULE_SRC_PORT: {
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "src_port=%u ",
                                         ntohs(pos->conditions[i].src_port));
                    break;
                }
                case RULE_DST_PORT: {
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "dst_port=%u ",
                                         ntohs(pos->conditions[i].dst_port));
                    break;
                }
                case RULE_SRC_MAC: {
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "src_mac=%pM ", pos->conditions[i].src_mac);
                    break;
                }
                case RULE_DST_MAC: {
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "dst_mac=%pM ", pos->conditions[i].dst_mac);
                    break;
                }
                case RULE_IPV4_PROTOCOL: {
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "proto=%u ", pos->conditions[i].dst_port);
                    break;
                }
                case RULE_CONTENT: {
                    struct content_rule *rule, *tmp;
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "contents= ");
                    list_for_each_entry_safe(
                        rule, tmp, &pos->conditions[i].content_list->head,
                        list) {
                        written +=
                            scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                      "|%s| ", rule->target_str);
                    }
                    break;
                }
                case RULE_TIME_DROP: {
                    struct time_rule *rule, *tmp;
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "time_drop= ");

                    list_for_each_entry_safe(
                        rule, tmp, &pos->conditions[i].time_list->head, list) {
                        written += scnprintf(
                            ptr + written, RULE_MSG_SIZE - written,
                            "|%02u:%02u-%02u:%02u| ", rule->start_hour, rule->start_min,
                            rule->end_hour, rule->end_min);
                    }

                    break;
                }
                case RULE_TIME_ACCEPT: {
                    struct time_rule *rule, *tmp;
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "time_accept= ");

                    list_for_each_entry_safe(
                        rule, tmp, &pos->conditions[i].time_list->head, list) {
                        written += scnprintf(
                            ptr + written, RULE_MSG_SIZE - written,
                            "|%02u:%02u-%02u:%02u| ", rule->start_hour, rule->start_min,
                            rule->end_hour, rule->end_min);
                    }

                    break;
                }
                case RULE_STATE_POLICY_DENY_ALL_NEW: {
                    written += scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                         "state-filte=true");
                    break;
                }
                case RULE_INTERFACE: {
                    written +=
                        scnprintf(ptr + written, RULE_MSG_SIZE - written,
                                  "dst_mac=%s ", pos->conditions[i].interface);
                    break;
                }
            }
        }
        written += scnprintf(ptr + written, RULE_MSG_SIZE - written, "\n");
    }
    memcpy(startptr, &j, sizeof(uint32_t));
    return total_size;
}

void del_parse_buffer(const char* msg_buffer_start_ptr) {
    // 解析buffer
    uint32_t* ptr = (uint32_t*)msg_buffer_start_ptr;
    uint32_t del_cnt = *((uint32_t*)ptr);
    ptr += 1;

    struct rule_list* black_list = get_rule_list(RULE_LIST_BLACK);
    struct rule_list* white_list = get_rule_list(RULE_LIST_WHITE);
    for (int i = 0; i < del_cnt; i++) {
        uint32_t del_rule_id = *ptr;
        if (del_rule(del_rule_id, black_list) ||
            del_rule(del_rule_id, white_list)) {
            // 删除成功

            continue;
        }
    }
}
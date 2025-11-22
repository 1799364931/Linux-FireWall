/*
 * time_filter.c - 时间过滤器实现
 */
#include "time_filter.h"

/**
 * time_filter_hook - Netfilter钩子函数
 */
unsigned int time_filter_hook(void* priv,
                              struct sk_buff* skb,
                              const struct nf_hook_state* state) {
    struct time_rule_list* rule_list;
    struct time_rule* time_rule;

    /* 检查SKB有效性 */
    if (!skb) {
        return NF_ACCEPT;
    }

    /* 获取规则列表 */
    rule_list = get_time_rule_list();
    if (!rule_list || list_empty(&rule_list->head)) {
        /* 没有规则，默认接受 */
        return NF_ACCEPT;
    }

    /* 遍历所有时间规则 */

    /*
        如果 现在时间∈规则包含时间 如果是丢弃则设置位图标记为True
        如果是接受则不设置

        如果 现在时间不属于规则包含时间 如果是丢弃就不管
        需要找到所有的接收时间的并集
    */
    struct black_list* black_list = get_black_list();

    struct rule_list_node* head = *(black_list->head);
    struct rule_list_node* mov = head->next;

    while (mov != NULL) {
        if (mov->rule_bitmap & RULE_TIME) {
            for (uint32_t i = 0; i < mov->match_condition_size; i++) {
                if (mov->rules[i].match_type == RULE_TIME) {
                    uint32_t accept_count = 0, drop_count = 0;
                    list_for_each_entry(time_rule,
                                        &mov->rules[i].time_list->head, list) {
                        /* 检查当前时间是否在规则范围内 */
                        if (check_time_in_range(
                                time_rule->start_hour, time_rule->start_min,
                                time_rule->end_hour, time_rule->end_min)) {
                            /* 更新匹配计数 */
                            if (time_rule->action = ACTION_ACCEPT) {
                                accept_count++;
                            } else {
                                drop_count++;
                            }
                        }
                    }
                    // 遍历完毕后判断是否应该丢弃
                    if (drop_count || !accept_count ) {
                        SKB_RULE_BITMAP(skb) |= RULE_CONTENT;
                    }
                }
            }
            if (mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
                return NF_DROP;
            }
            mov = mov->next;
        }
    }

    /* 没有匹配的规则，默认接受 */
    return NF_ACCEPT;
}

/**
 * check_time_in_range - 检查当前时间是否在指定范围内
 */
int check_time_in_range(int start_hour,
                        int start_min,
                        int end_hour,
                        int end_min) {
    struct timespec64 ts;
    struct tm tm_now;
    int current_minutes, start_minutes, end_minutes;
    time64_t local_time;

    /* 获取当前时间 */
    ktime_get_real_ts64(&ts);

    /* 转换为本地时间 (假设UTC+8) */
    local_time = ts.tv_sec + 8 * 3600;
    time64_to_tm(local_time, 0, &tm_now);

    /* 将时间转换为分钟数，便于比较 */
    current_minutes = tm_now.tm_hour * 60 + tm_now.tm_min;
    start_minutes = start_hour * 60 + start_min;
    end_minutes = end_hour * 60 + end_min;

    /* 处理跨天情况 (如 23:00-01:00) */
    if (start_minutes > end_minutes) {
        /* 跨天规则：在开始时间之后或结束时间之前 */
        return (current_minutes >= start_minutes ||
                current_minutes <= end_minutes);
    } else {
        /* 同天规则：在开始和结束时间之间 */
        return (current_minutes >= start_minutes &&
                current_minutes <= end_minutes);
    }
}

#ifndef _BUFFER_PARSER_H
#define _BUFFER_PARSER_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "../../../public_structs/match_condition_msg.h"
#include "../../../public_structs/rule_bitmap.h"
#include "../../rule/rule.h"
// 构造一个rule_list_node的数据结构

#define RULE_MSG_SIZE 512
void parse_buffer(const char* msg_buffer_start_ptr);

// 获取对应的信息
uint32_t build_rule_list_msg(char** target_buffer_ptr,enum rule_list_type type);

#endif
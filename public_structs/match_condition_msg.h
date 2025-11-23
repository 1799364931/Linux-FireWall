
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define MAC_LENGTH 6

struct match_condition_msg {
    uint64_t match_type;
    union {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint32_t src_mask_ip;
        uint32_t dst_mask_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t ipv4_protocol;
        uint8_t src_mac[MAC_LENGTH];
        uint8_t dst_mac[MAC_LENGTH];
    };
    // buffer
    uint32_t buffer_offset;
    uint32_t buffer_len;
};

struct rule_entry_msg {
    uint32_t condition_count;  // 条件数量
    uint64_t bitmap;
    struct match_condition_msg conditions[];
    // 后面跟附加 buffer
};
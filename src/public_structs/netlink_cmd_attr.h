
enum {
    CMD_UNSPEC,
    CMD_ADD_RULE,  // 用户态要调用的命令
    CMD_CHANGE_MOD,
    CMD_LIST_RULE,
    CMD_DEL_RULE,
    CMD_LIST_RULE_REPLY,
    CMD_ADD_RULE_REPLY,
    CMD_CHANGE_MOD_REPLY,
    CMD_DEL_RULE_REPLY,
};

enum {
    ATTR_UNSPEC,
    ATTR_BUF,  // 用户态传递的缓冲区
    ATTR_BLACK_LIST,
    ATTR_WHITE_LIST,
    __ATTR_MAX,
};

#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)
enum {
    CMD_UNSPEC,
    CMD_ADD_RULE,
    CMD_CHANGE_MOD,
    CMD_LIST_RULE,
    CMD_DEL_RULE,
    CMD_LIST_RULE_REPLY,
    CMD_ADD_RULE_REPLY,
    CMD_CHANGE_MOD_REPLY,
    CMD_DEL_RULE_REPLY,
    
    /* 新增：Rate Limiter 命令 */
    CMD_ADD_RATE_LIMIT,           /* 添加限速规则 */
    CMD_DEL_RATE_LIMIT,           /* 删除限速规则 */
    CMD_LIST_RATE_LIMIT,          /* 列出限速规则 */
    CMD_RESET_RATE_LIMIT_STATS,   /* 重置限速统计 */
    CMD_ADD_RATE_LIMIT_REPLY,
    CMD_DEL_RATE_LIMIT_REPLY,
    CMD_LIST_RATE_LIMIT_REPLY,
    CMD_RESET_RATE_LIMIT_STATS_REPLY,

    CMD_LOGGING_REGISTER,
    CMD_LOGGING_REGISTER_REPLY,
    CMD_LOGGING_FETCH,
};

enum {
    ATTR_UNSPEC,
    ATTR_BUF,
    ATTR_BLACK_LIST,
    ATTR_WHITE_LIST,
    
    /* 新增：Rate Limiter 属性 */
    ATTR_RATE_LIMIT_LIST,

    ATTR_LOG,
    
    __ATTR_MAX,
};

#define MY_ATTR_MAX (__ATTR_MAX - 1)
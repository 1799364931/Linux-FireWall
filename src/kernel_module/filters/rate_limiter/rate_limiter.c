// kernel_module/filters/rate_limiter/rate_limiter.c
#include "rate_limiter.h"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include "rate_limiter_list.h"

MODULE_AUTHOR("Kotori");
MODULE_DESCRIPTION("Rate Limiter for Firewall");

/* 全局规则列表 */
struct rate_limit_rule_list* g_rate_limit_list = NULL;
struct mutex rate_limit_list_lock;
DEFINE_MUTEX(rate_limit_list_lock);

/* 初始化全局列表 */
struct rate_limit_rule_list* get_rate_limit_list(void) {
    if (g_rate_limit_list == NULL) {
        g_rate_limit_list = kzalloc(sizeof(struct rate_limit_rule_list), 
                                    GFP_KERNEL);
        if (!g_rate_limit_list)
            return NULL;
        
        INIT_LIST_HEAD(&g_rate_limit_list->head);
        mutex_init(&g_rate_limit_list->lock);
        g_rate_limit_list->count = 0;
        g_rate_limit_list->next_rule_id = 1;
    }
    return g_rate_limit_list;
}

/**
 * 从数据包中提取源/目标IP和端口
 */
static int extract_ip_port_info(struct sk_buff *skb,
                                uint32_t *src_ip,
                                uint32_t *dst_ip,
                                uint16_t *src_port,
                                uint16_t *dst_port) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    
    iph = ip_hdr(skb);
    if (!iph)
        return -1;
    
    *src_ip = iph->saddr;
    *dst_ip = iph->daddr;
    
    /* 对于TCP和UDP，尝试提取端口 */
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2));
        if (tcph) {
            *src_port = tcph->source;
            *dst_port = tcph->dest;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)(skb->data + (iph->ihl << 2));
        if (udph) {
            *src_port = udph->source;
            *dst_port = udph->dest;
        }
    }
    
    return 0;
}

/**
 * 检查数据包是否与规则匹配
 */
static bool match_rate_limit_rule(struct rate_limit_rule *rule,
                                  uint32_t src_ip,
                                  uint32_t dst_ip,
                                  uint16_t src_port,
                                  uint16_t dst_port) {
    if (rule->src_ip != 0 && rule->src_ip != src_ip)
        return false;
    
    if (rule->dst_ip != 0 && rule->dst_ip != dst_ip)
        return false;
    
    if (rule->src_port != 0 && rule->src_port != src_port)
        return false;
    
    if (rule->dst_port != 0 && rule->dst_port != dst_port)
        return false;
    
    return true;
}

/**
 * 令牌桶算法：补充令牌
 */
static void refill_tokens(struct rate_limit_rule *rule) {
    unsigned long now = get_jiffies_64();
    unsigned long time_elapsed;
    uint32_t new_tokens;
    
    if (rule->last_refill == 0) {
        rule->last_refill = now;
        rule->tokens = rule->max_tokens;
        return;
    }
    
    time_elapsed = now - rule->last_refill;
    
    /* 计算应该补充的令牌数 */
    /* refill_rate 是 pps，所以需要除以 HZ 得到秒数 */
    new_tokens = (time_elapsed * rule->refill_rate) / HZ;
    
    rule->tokens = min(rule->max_tokens, rule->tokens + new_tokens);
    rule->last_refill = now;
}

/**
 * 检查是否允许数据包通过
 * 返回：true 允许，false 丢弃
 */
static bool check_rate_limit(struct rate_limit_rule *rule,
                             struct sk_buff *skb) {
    bool allowed;
    
    spin_lock_bh(&rule->lock);
    
    refill_tokens(rule);
    
    if (rule->tokens > 0) {
        rule->tokens--;
        rule->packets_allowed++;
        rule->bytes_allowed += skb->len;
        allowed = true;
    } else {
        rule->packets_dropped++;
        rule->bytes_dropped += skb->len;
        allowed = false;
    }
    
    spin_unlock_bh(&rule->lock);
    
    return allowed;
}

unsigned int rate_limiter_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *rule, *n;
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t traffic_direction;  /*新增：当前数据包的方向 */
    
    // static unsigned long last_print = 0;
    // unsigned long now = get_jiffies_64();
    
    // // 每秒打印一次（避免日志爆炸）
    // if (time_after(now, last_print + HZ)) {
    //     // printk(KERN_INFO "rate_limiter_hook: called, packets processed\n");
    //     last_print = now;
    // }
    
    /* 获取规则列表 */
    list = get_rate_limit_list();
    if (!list || list->count == 0)
        return NF_ACCEPT;
    
    /* 从数据包中提取IP和端口信息 */
    if (extract_ip_port_info(skb, &src_ip, &dst_ip, &src_port, &dst_port) < 0)
        return NF_ACCEPT;
    
    /*根据钩子点判断流量方向 */
    if (state->hook == NF_INET_LOCAL_IN) {
        traffic_direction = 0;  /* 入站 */
    } else if (state->hook == NF_INET_LOCAL_OUT) {
        traffic_direction = 1;  /* 出站 */
    } else {
        /* 其他钩子点，允许通过 */
        return NF_ACCEPT;
    }
    
    /* 遍历规则列表（按优先级排序） */
    mutex_lock(&list->lock);
    list_for_each_entry_safe(rule, n, &list->head, list) {
        if (!rule->enabled)
            continue;
        
        /*  新增：检查方向是否匹配 */
        if (rule->direction != traffic_direction) {
            continue;  /* 方向不匹配，跳过此规则 */
        }
        
        /* 检查规则是否匹配 */
        if (match_rate_limit_rule(rule, src_ip, dst_ip, src_port, dst_port)) {
            printk(KERN_INFO "rate_limiter: matched rule %u, direction=%s, src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u\n",
                   rule->rule_id,
                   traffic_direction == 0 ? "INBOUND" : "OUTBOUND",
                   &src_ip, &dst_ip, ntohs(src_port), ntohs(dst_port));
            
            /* 规则匹配，进行限速检查 */
            bool allowed = check_rate_limit(rule, skb);
            mutex_unlock(&list->lock);
            
            if (allowed) {
                printk(KERN_DEBUG "rate_limiter: packet allowed, rule_id=%u\n",
                       rule->rule_id);
                return NF_ACCEPT;
            } else {
                printk(KERN_INFO "rate_limiter: packet dropped, rule_id=%u\n",
                       rule->rule_id);
                return NF_DROP;
            }
        }
    }
    mutex_unlock(&list->lock);
    
    /* 没有规则匹配，允许通过 */
    return NF_ACCEPT;
}

/**
 * 创建新的限速规则
 */
struct rate_limit_rule* create_rate_limit_rule(uint32_t refill_rate,
                                               uint32_t max_tokens,
                                               uint32_t src_ip,
                                               uint32_t dst_ip,
                                               uint16_t src_port,
                                               uint16_t dst_port,
                                               uint32_t priority,
                                               uint8_t direction) {
    struct rate_limit_rule *rule;
    struct rate_limit_rule_list *list;
    
    list = get_rate_limit_list();
    if (!list)
        return NULL;
    
    rule = kzalloc(sizeof(struct rate_limit_rule), GFP_KERNEL);
    if (!rule)
        return NULL;
    
    INIT_LIST_HEAD(&rule->list);
    spin_lock_init(&rule->lock);
    
    /* 分配规则ID */
    mutex_lock(&rate_limit_list_lock);
    rule->rule_id = list->next_rule_id++;
    mutex_unlock(&rate_limit_list_lock);
    
    rule->refill_rate = refill_rate;
    rule->max_tokens = max_tokens;
    rule->tokens = max_tokens;  /* 初始时桶满 */
    rule->src_ip = src_ip;
    rule->dst_ip = dst_ip;
    rule->src_port = src_port;
    rule->dst_port = dst_port;
    rule->priority = priority;
    rule->direction = direction;  /* ← 设置方向 */
    rule->enabled = true;
    rule->last_refill = get_jiffies_64();
    rule->last_stat_reset = rule->last_refill;
    
    printk(KERN_INFO "rate_limiter: created rule %u (rate=%u pps, max=%u, direction=%s)\n",
           rule->rule_id, refill_rate, max_tokens,
           direction == 0 ? "INBOUND" : "OUTBOUND");
    
    return rule;
}

/**
 * 销毁限速规则
 */
void destroy_rate_limit_rule(struct rate_limit_rule* rule) {
    if (!rule)
        return;
    
    kfree(rule);
}

/**
 * 添加限速规则到列表（按优先级排序）
 */
bool add_rate_limit_rule(struct rate_limit_rule* rule) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *pos;
    
    if (!rule)
        return false;
    
    list = get_rate_limit_list();
    if (!list)
        return false;
    
    mutex_lock(&list->lock);
    
    /* 检查是否已存在相同ID */
    list_for_each_entry(pos, &list->head, list) {
        if (pos->rule_id == rule->rule_id) {
            mutex_unlock(&list->lock);
            return false;
        }
    }
    
    /* 按优先级插入 */
    list_for_each_entry(pos, &list->head, list) {
        if (pos->priority > rule->priority) {
            list_add_tail(&rule->list, &pos->list);
            list->count++;
            mutex_unlock(&list->lock);
            printk(KERN_INFO "rate_limiter: added rule %u to list\n",
                   rule->rule_id);
            return true;
        }
    }
    
    /* 添加到列表末尾 */
    list_add_tail(&rule->list, &list->head);
    list->count++;
    mutex_unlock(&list->lock);
    
    printk(KERN_INFO "rate_limiter: added rule %u to list\n", rule->rule_id);
    return true;
}

/**
 * 删除限速规则
 */
bool del_rate_limit_rule(uint32_t rule_id) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *rule, *n;
    
    list = get_rate_limit_list();
    if (!list)
        return false;
    
    mutex_lock(&list->lock);
    list_for_each_entry_safe(rule, n, &list->head, list) {
        if (rule->rule_id == rule_id) {
            list_del(&rule->list);
            list->count--;
            destroy_rate_limit_rule(rule);
            mutex_unlock(&list->lock);
            
            printk(KERN_INFO "rate_limiter: deleted rule %u\n", rule_id);
            return true;
        }
    }
    mutex_unlock(&list->lock);
    
    return false;
}

/**
 * 查找限速规则
 */
struct rate_limit_rule* find_rate_limit_rule(uint32_t rule_id) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *rule;
    
    list = get_rate_limit_list();
    if (!list)
        return NULL;
    
    mutex_lock(&list->lock);
    list_for_each_entry(rule, &list->head, list) {
        if (rule->rule_id == rule_id) {
            mutex_unlock(&list->lock);
            return rule;
        }
    }
    mutex_unlock(&list->lock);
    
    return NULL;
}

/**
 * 重置限速规则的统计信息
 */
void reset_rate_limit_stats(uint32_t rule_id) {
    struct rate_limit_rule *rule;
    
    rule = find_rate_limit_rule(rule_id);
    if (!rule)
        return;
    
    spin_lock_bh(&rule->lock);
    rule->packets_dropped = 0;
    rule->packets_allowed = 0;
    rule->bytes_dropped = 0;
    rule->bytes_allowed = 0;
    rule->last_stat_reset = get_jiffies_64();
    spin_unlock_bh(&rule->lock);
    
    printk(KERN_INFO "rate_limiter: reset stats for rule %u\n", rule_id);
}

/**
 * 启用/禁用限速规则
 */
void enable_rate_limit_rule(uint32_t rule_id, bool enable) {
    struct rate_limit_rule *rule;
    
    rule = find_rate_limit_rule(rule_id);
    if (!rule)
        return;
    
    spin_lock_bh(&rule->lock);
    rule->enabled = enable;
    spin_unlock_bh(&rule->lock);
    
    printk(KERN_INFO "rate_limiter: rule %u %s\n",
           rule_id, enable ? "enabled" : "disabled");
}

/**
 * 初始化模块
 */
int rate_limiter_init(void) {
    struct rate_limit_rule_list *list;
    
    printk(KERN_INFO "rate_limiter: initializing...\n");
    
    list = get_rate_limit_list();
    if (!list) {
        printk(KERN_ERR "rate_limiter: failed to initialize list\n");
        return -ENOMEM;
    }
    
    printk(KERN_INFO "rate_limiter: initialized successfully\n");
    return 0;
}

/**
 * 清理模块
 */
void rate_limiter_cleanup(void) {
    struct rate_limit_rule_list *list;
    struct rate_limit_rule *rule, *n;
    
    printk(KERN_INFO "rate_limiter: cleaning up...\n");
    
    list = get_rate_limit_list();
    if (!list)
        return;
    
    mutex_lock(&list->lock);
    list_for_each_entry_safe(rule, n, &list->head, list) {
        list_del(&rule->list);
        destroy_rate_limit_rule(rule);
    }
    list->count = 0;
    mutex_unlock(&list->lock);
    
    kfree(list);
    g_rate_limit_list = NULL;
    
    printk(KERN_INFO "rate_limiter: cleaned up\n");
}
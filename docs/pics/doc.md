# Linux 个人防火墙实验报告

## 1 实验目的

实现在Linux下的个人防火墙，实现功能：
+ 实时过滤，按安全规则对进出本机的数据包进行按规则过滤，过滤规则支持：
    + IP地址过滤
    + IP掩码过滤
    + MAC地址过滤
    + 端口过滤
    + IP协议过滤
    + 时间过滤
    + 包内负载字符串过滤
    + 网络接口过滤
    + 连接状态过滤
+ 黑白名单规则添加、删除、显示、切换。
+ 日志记录网络访问详细信息。
+ 截获时进行用户提示。
+ 命令行与网页界面交互。
    

## 2 实验环境和工具

### 2.1 实验环境
系统环境：Linux Ubuntu24.04.1 LTS \
编程环境：
+ 内核代码：C99
+ 用户态代码：C++17
+ 后端代码：Python 3.8
+ 前端代码：Vue

### 2.2 工具
+ VMware 虚拟机以运行Linux环境
+ vscode 进行代码编写和执行

## 3 设计与实现


### 3.1 架构设计

防火墙的架构主要分为四大模块：

+ 内核态：防火墙核心功能组件，截获并解析进出本机的数据包，按规则对数据包进行拦截或放行。

+ 用户态：防火墙交互组件，将用户命令输入解析为安全规则和指令，向内核态的防火墙发送对应信息，以实现安全规则的增删查等常用功能。

+ 网页后端：防火墙远程交互功能的后端程序，用于解析前端发送的请求为对应的命令，调用用户态程序以实现防火墙控制功能。

+ 网页前端：防火墙远程交互功能的前端程序，优化用户对防火墙的控制交互与规则增添删除等功能的友好性。

#### 3.1.1 内核态模块设计

防火墙的内核态模块主要负责以下功能：
+ 管理安全规则
+ 与用户态进行通信
+ 解析用户发送的结构体信息，并执行对应的规则操作
+ 挂载`hook function`到对应的挂载点，对进出本机的数据包进行解析和捕获

因此，内核态模块主要由以下项组成
```
kernel_module
    |_ communicate
    |        |_ buffer_parse # 解析用户发送的netlink数据包
    |        |_ netlink_module # 管理通信模块，进行netlink数据包的接收和发送
    |
    |_ filters # 安全规则的过滤钩子函数的实现
    |
    |_ rule # 管理安全规则链表，负责节点的增加、删除、初始化、释放
    
```

#### 3.1.2 用户态模块设计

防火墙的用户态模块主要负责以下功能：
+ 接受用户的从命令行输入的命令，并解析为相应的防火墙控制操作
+ 将对应的命令信息通过netlink通信机制存放到netlink数据包内，发送给内核
+ 接收内核返回的响应信息



#### 3.1.3 用户-内核通信设计

在`Linux`中，内核态和用户态无法直接共享内存地址，同时可用的库文件也不一致，故用户-内核通信需要跨进程进行。

在本实验中，采用`Netlink`作为内核态与用户态的通信机制。`Netlink` 是 `Linux` 内核提供的一种基于 `socket` 的通信机制，
专门用于用户态与内核态之间的双向消息传递。

##### 3.1.3.1 内核态

在内核态中，使用`genetlink`库实现`Netlink`内核模块。

对于信息的接收和处理，首先定义命令表、属性表、对应属性的解析策略表、操作命令表，即接收到对应的命令，需要调用哪些回调函数，同时以哪种策略接收该属性的信息：

```c
enum {
    CMD_UNSPEC,
    CMD_ADD_RULE,  // 用户态要调用的命令
    //省略 ....
};

enum {
    ATTR_UNSPEC,
    ATTR_BUF,  // 用户态传递的缓冲区
    // 省略 ... 
};


const struct nla_policy my_policy[__ATTR_MAX + 1] = {
    [ATTR_BUF] = {.type = NLA_BINARY},  // 定义为二进制数据
    [ATTR_BLACK_LIST] = {.type = NLA_BINARY},
    [ATTR_WHITE_LIST] = {.type = NLA_BINARY}
};


const struct genl_ops my_ops[] = {
    {
        .cmd = CMD_ADD_RULE, // 命令
        .flags = 0,
        .policy = my_policy, // 解析策略
        .doit = handle_recv_add_rule_msg,  // 回调函数
    }
    // 省略 ....
    }
```

在接收完毕后，即可进行对应的操作处理，以添加规则为例：

```c
int handle_recv_add_rule_msg(struct sk_buff* skb, struct genl_info* info) {
    if (!info->attrs[ATTR_BUF]) {
        pr_err("netlink: missing buffer attribute\n");
        return -EINVAL;
    }

    const void* buf = nla_data(info->attrs[ATTR_BUF]);
    parse_buffer(buf);

    char* reply_msg = kmalloc(REPLY_MSG_SIZE, GFP_KERNEL);
    sprintf(reply_msg, "add rule success");

    // 返回成功添加的信息
    send_msg_to_user(reply_msg, REPLY_MSG_SIZE, info, CMD_ADD_RULE_REPLY);

    kfree(reply_msg);
    return 0;
}

```

对于信息的发送，则通过用户态发送的`info`作为上下文信息，单播回给用户态程序：

```c
int send_msg_to_user(const char* msg_buf,
                      int msg_len,
                      struct genl_info* info,
                      int cmd) {
    struct sk_buff* skb;
    void* hdr;

    //开辟空间
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;
    
    //填充头部
    hdr = genlmsg_put(skb, info->snd_portid, info->snd_seq, &my_family, 0, cmd);

    if (!hdr) {
        nlmsg_free(skb);
        return -ENOMEM;
    }

    // 填充属性数据
    if (nla_put(skb, ATTR_BUF, msg_len, msg_buf)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    // 构造信息
    genlmsg_end(skb, hdr);
    // 单播给用户进程
    return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}
```

##### 3.1.3.2 用户态

用户态则使用`libnl3`包装的`Netlink`库实现`Netlink`通信模块，包装该类为`netlink_tool`。

实现以下四个函数以进行初始化、发送和接收。具体的实现和内核态类似，只不过调用的库包装`api`不同。
```cpp
    bool init();

    bool send_buffer(const char* startpos,
                     uint32_t bufferlen,
                     int cmd,
                     int attr);

    static int recv_msg(struct nl_msg* msg, void* arg);

    bool recv_once();
```

#### 3.1.4 网页交互设计

### 3.2 防火墙功能设计

#### 3.2.1 `hook function`设计

防火墙的包截获与拦截实现即为在对应的挂载点利用`Netfilter`库挂载对应的`hook function`以解析流经挂载点的数据包，从而获取数据包对应的信息，以实现在进出本机时候对数据包进行过滤拦截。

本实验中防火墙大部分`hook function`的设计相似，即读取数据包信息，若满足当前`hook function`的过滤规则，则打上对应的位图标记，若完全满足某一条安全规则，则根据当前放行模式(黑名单/白名单)对数据包进行相应处理(拦截/放行)。

##### 3.2.1.1 IP地址过滤

#### 3.2.2 规则结构设计

防火墙的规则结构主要由两个链表实现，即黑名单链表与白名单链表。而这两个链表的结构实现是类似的，因而下面只考虑黑名单链表。

安全规则的层次结构为，黑名单->安全规则->过滤条件。以安全规则
`src_ip = 123.123.123.123 dst_port = 22`为例，则`src_ip`和`dst_port`都属于其过滤条件。

具体代码实现位于`src/kernel_module/rule/rule.h`：
```
BLACK_LIST {
    # 一个节点代表一个安全规则
    RULE_LIST_NODE_1 { 
        struct match_condition* conditions{
            # 一个condition节点代表一个规则中的某一个过滤条件
            CONDITION_1{
                src_ip
            },
            CONDITION_2{
                dst_ip
            },
            CONDITION_3{
                # 对于如多字符串匹配过滤，则其条件中含有多个
                contents{
                    str1,
                    str2
                    ...
                }
            },
            ....
        };
        uint32_t condition_count;
        uint32_t rule_id;
        uint64_t rule_bitmap;
    },
    RULE_LIST_NODE_2{
        ...
    },
    RULE_LIST_NODE_3{
        ...
    }...
}
```

#### 3.2.3 防火墙拦截设计

基于黑名单和白名单的过滤设计类似，拦截设计首先基于黑名单讨论。
由于`hook function`挂载后存在顺序性，同时一个规则存在多个过滤条件，所以一个数据包需要经过多个`hook function`才能确定被拦截丢弃。

故考虑利用数据包保留字段，`skb->cb`来存储一个64位的位图，同时给每一种过滤条件都赋予一个过滤类型，每一种类型对应着位图的一个位。

当一个数据包流经`hook function`的时候，该`hook function`先遍历所有的安全规则，若该数据包满足某个安全规则的过滤条件A，则在A对应位上打上标记，说明满足改过滤条件A。若对于某个数据包，其标记位图恰好等于某个安全规则的规则位图，则说明该数据包在被多个`hook function`处理后，满足某个安全规则。此时在黑名单条件下，该数据包会被丢弃。

对于白名单条件，则在最后的`hook function`以处理所有数据包，若数据包满足某一白名单安全规则，则进行放行，否则丢弃。而黑名单条件可以在中途丢弃数据包。

以IP过滤为例：

```cpp
list_for_each_entry(mov, &rule_list->nodes, list) {
    // 判断是否有IP相关的 过滤规则，减少遍历
    if (mov->rule_bitmap & (RULE_IP_FILTER)) {
        for (uint32_t i = 0; i < mov->condition_count; i++) {
            switch (mov->conditions[i].match_type) {
                case RULE_SRC_IP: {
                    if (iph->saddr == mov->conditions[i].src_ip) {
                        // 如果满足条件就打上标记
                        SKB_RULE_BITMAP(skb) |= RULE_SRC_IP;
                    }
                    break;
                }
                case RULE_SRC_IP_MASK: {
                    if (ip_match_prefix(iph->saddr,
                                        mov->conditions[i].src_mask_ip)) {
                        SKB_RULE_BITMAP(skb) |= RULE_SRC_IP_MASK;
                    }
                    break;
                }
                case RULE_DST_IP: {
                    if (iph->daddr == mov->conditions[i].dst_ip) {
                        SKB_RULE_BITMAP(skb) |= RULE_SRC_IP;
                    }
                    break;
                }
                case RULE_DST_IP_MASK: {
                    if (ip_match_prefix(iph->daddr,
                                        mov->conditions[i].dst_mask_ip)) {
                        SKB_RULE_BITMAP(skb) |= RULE_DST_IP_MASK;
                    }
                    break;
                }
                default:
                    continue;
            }
        }
    }
    // 如果当前数据包使用黑名单规则，且满足安全过滤规则，则丢弃
    if (ENABLE_BLACK_LIST(skb) && mov->rule_bitmap == SKB_RULE_BITMAP(skb)) {
        return NF_DROP;
    }
}
```
#### 3.2.4 规则通信序列化设计

由于用户态程序对输入的命令行解析为对应的安全规则结构，而安全规则的数据结构组织有以下特征：
+ 不定长，不同规则所需的过滤条件数量不同，同时对于字符串过滤，待匹配字符串的数量也不同。
+ 包含地址变量，对于字符串结构，其在安全规则结构中保存的是字符串地址，而非整体的字符串。而用户态和内核态内存无法共享。
+ 内核态代码受限，由于内核态需要严格遵循C语言标准，且无法使用用户态头文件，故难以采用类似于`json`这样的方式进行简易的反序列化。
+ 内核态与用户态代码规范不同，只能最低程度共享C语言标准的结构体形式。





### 3.3 日志记录设计

### 3.4 用户交互设计

#### 3.4.1 命令行设计

#### 3.4.2 前后端设计

## 4 实验结果

## 5 改进和拓展方向


## 6 总结


## 7 小组成员及分工


## 8 参考文献
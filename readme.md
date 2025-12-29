# Linux 个人防火墙

## 1 配置环境与运行方式

## 1.1 运行环境

本程序需要在如下环境运行：
+ Ubuntu 24.04.1 LTS 及以上环境
+ lib库中配置 6.14.0-37-generic 及以上Linux内核头文件
+ 支持`gnu99`和`gnu++17`的编译器
+ `make`工具

## 1.2 运行方式

防火墙支持两种界面交互，即命令行界面与网页界面交互。无论哪一种交互方式，
都需要防火墙运行在系统内核层，并且通过用户态的命令行控制程序来发送命令和接收防火墙信息，同时日志信息通过另一个日志程序接收。

### 1.2.1 防火墙内核程序

#### 1.2.1.1 程序编译加载

防火墙的内核程序运行在系统内核，完成主要的防火墙过滤，日志监控，命令接收等功能。

首先需要在`src/kernel_module/`文件目录下，执行`make`命令以编译程序。在编译成功后，得到`myfirewall.ko`内核模块文件，然后通过执行命令
```shell
sudo insmod myfirewall.ko
```
将内核模块加载到系统内核并执行。

最终通过`sudo dmesg`获取内核日志，确认防火墙启动成功。
![alt text](image.png)

#### 1.2.1.2 程序卸载

防火墙通过内核模块卸载命令进行卸载关闭，通过执行命令
```shell
sudo rmmod myfirewall.ko
```
将防火墙内核模块进行关闭，可以通过`sudo dmesg`确认关闭成功。
![alt text](image-2.png)

### 1.2.2 防火墙控制程序

防火墙控制程序主要通过解析用户输入的命令，将对应的数据信息发送给防火墙内核以执行对应的安全规则和控制方式。

首先需要进入`src/usr/controller`目录下，执行`make`命令以编译程序，得到`firewall`程序，该程序需要在内核程序运行完毕后才能正常工作。

通过`--help`参数，可以获取程序所支持的安全规则与控制方式：

![alt text](image-3.png)

#### 1.2.2.1 命令行设计
```shell
./firewall [命令] [选项1] [参数1] [选项2] [参数2]  
```

##### 1.2.2.1.1 命令
+ add 增加规则
+ del 删除规则
+ list 输出当前规则
+ mode 更改名单规则

##### 1.2.2.1.2 选项
+ `--src-ip`
+ `--dst-ip`
+ `--src-ip-mask`
+ `--dst-ip-mask`
+ `--dst-port`
+ `--src-port`
+ `--dst-mac`
+ `--src-mac`
+ `--proto` 要过滤的IPV4协议
+ `--time-drop` 丢弃这段时间内的数据包
+ `--time-accept` 只允许这段时间内的数据包
+ `--est` 只允许建立连接的数据包通过
+ `--content "str1" "str2" "str3" ....` 过滤包含这些关键字的包
+ `--interface` 过滤对应的接口
+ `--drop / --accept` 黑名单/白名单模式下有效
+ `w/W b/B` 更改黑/白名单

#### 1.2.2.2  命令行实例

##### 1.2.2.2.1 --add
`--add`参数用于增加规则，其必须包含`--drop`或`--accept`参数来指明增加的规则是属于黑名单规则还是白名单规则，即对满足匹配规则的数据包进行丢弃还是接受。

```shell
# 过滤进入本机的，源IP地址为:123.123.123.123 目标端口为:80 的数据包
./firewall --add --src-ip 123.123.123.123 --dst-port 80 --drop

# 过滤进入本机的，源MAC地址为：00:0c:29:09:f2:b0 协议为：icmp 的数据包
./firewall --add --src-mac  00:0c:29:09:f2:b0 --proto icmp --drop

# 在12:00 - 14:00 时间段内丢弃所有源地址为：123.123.123.123 内容负载包含：abcd 或 efg 的数据包
./firewall --add --time-drop "12:00 14:00" --src-ip 123.123.123.123 --content ""abcd" "efg"" --drop

# 过滤所有非已建立连接的数据包
./firewall --add --est 1 --drop

# 只允许icmp协议数据包进入本机
./firewall --add --proto icmp --accept

# 只允许通过本机 ens12 网络接口，源地址IP网段属于123.123.0.0的数据包进入本机
./firewall --add --src-ip-mask 123.123.0.0 --interface ens12 --accept

```

##### 1.2.2.2.2 --list

``--list``参数用于列出当前已存在的防火墙规则。

```shell
./firewall --list
```
![alt text](image-4.png)

##### 1.2.2.2.3 --del

`--del`参数接受一个`rule id`即`--list`返回的`Rule {rule id}`，以删除选中的规则。

```shell
# 删除Rule 0规则 ，见上图
./firewall --del 0
```
![alt text](image-5.png)

##### 1.2.2.2.4 --mode
`--mode` 参数接受一个字符以改变防火墙的名单过滤规则，切换黑/白名单过滤。

```shell
# 切换为白名单
./firewall --mode w

./firewall --mode W

# 切换为黑名单
./firewall --mode b

./firewall --mode B
```


## 1 实现功能

### 1.1 安全规则

+ 基于IP的过滤：根据源IP或目标IP地址进行过滤。
+ 基于端口的过滤：针对TCP和UDP，根据源端口或目标端口进行过滤。
+ 基于协议的过滤：根据IP协议类型进行过滤。
+ 基于MAC地址的过滤：根据源MAC或目标MAC地址进行过滤。
+ 基于包状态的过滤：只允许已建立连接的数据包通过。
+ 基于数据包内容的过滤：检查数据包负载中的特定字符串或模式。
+ 基于时间段的过滤：在特定时间段内启用或禁用规则。
+ 基于网络接口的过滤：根据数据包进入或离开的网络接口进行过滤。
+ 流量限制：限制某个IP或端口的流量速率。
+ 日志记录：对流经防火墙的数据包进行监控。


 
 ### 1.2.4 日志输出
 
 日志文件程序为`logger`，需要在内核态程序启动后才能运行。

 该文件通过一个大小为1024的缓冲队列接收日志，并且每隔一秒打印32条最新的日志，当队列中日志过多时，会优先丢弃旧日志，从而保证队列中的日志总是最新的。

 


## 2 框架设计

### 2.1 安全规则设计
利用`netfilter`库对挂载点进行`hook function`挂载，利用挂载链实现挂载过滤函数复用和逻辑拆分。

#### 2.1.1 PRE_ROUTING
+ IP 过滤
+ 基础协议过滤
+ 流量速率限制

#### 2.1.2 LOCAL_IN
+ 端口访问规则
+ 连接状态管理
+ 应用层协议过滤
+ IP 过滤
+ 基础协议过滤
+ 流量速率限制

### 2.2 安全规则挂载

定义一个规则结构体链表，所有挂载的`hook function`在挂载前都需要对该链表进行遍历，从而获得过滤的规则

IP 端口 协议 MAC

利用skb->cb存储上下文信息，用skb的cb数组存储一个8字节的位图，对每一类规则，比如说源ip，源端口，都赋予一个位图上的位，比如0x1，0x2，当数据包在钩子函数流动的时候，每次如果满足被过滤的规则，就在位图对应位置置1，如果在某一个钩子函数中，该位图和原有的规则位图相等，则说明所有过滤条件满足，丢弃该包。

### 2.3 用户和内核通信

总体框架实现如下：

(用户态) 发送信息(命令/配置文件信息) => (用户态) 解析规则信息 => (内核态)netlink传输规则结构体 => (内核态)添加规则链表 

过滤规则 <= hook function <= 获取规则链表 

#### 2.3.1 通信数据组织

内核和用户态通信有以下**局限**：
+ 内核模块和用户模块采用的头文件和语言不同，一个公共结构体需要满足两种编译方式。
+ 内核和用户无法共享内存空间，用户态所实现的数据无法通过指针直接传递给内核，需将原始数据一并传递。
+ 原始数据包含字符串等不定长的数据结构，若采用定长数据结构，则会导致结构体中大量内存被浪费。

因此通信采用自定数据序列化的方式：
+ 提取一个最小的可用公共结构体，将可利用`union`存储的定长信息存储在结构体中。
+ 额外存储一个数据缓冲区，将不定长的数据存储到数据缓冲区中，并且每一个数据都存储一个元数据头，便于反序列化。
+ 采用柔性数组，以解决单个规则节点的匹配规则不定长的问题。

内核与用户通信的数据缓冲区组织形式如下：

```
| rule_entry_msg | extra_data_buffer |

| rule_entry_msg | 
    |
    └ | condition_count [4 bytes] | padding zero [4 bytes] | bitmap [8 bytes] | 
        | conditions[0] | conditions[1] | ..... | conditions[condition_count-1] |  

| extra_data_buffer|
    |
    └ | contents | times | interface |

| contents |
    |
    └ | contents_count [4 bytes] | content1_length(without '\0') [4 bytes] | content1 [content1_length * 4 bytes] | .... | contentN_length(without '\0') [4 bytes] | contentN [content1_length * 4 bytes] |

| times | 
    |
    └ | time_pair_count [4 bytes] | pair1_start_hour [4 bytes] | pair1_start_minute [4 bytes] | pair1_end_hour [4 bytes] | pair1_end_minute [4 bytes] .... | pairN_start_hour [4 bytes] | pairN_start_minute [4 bytes] | pairN_end_hour [4 bytes] | pairN_end_minute [4 bytes] |

| interface |
    |
    └ | interface_str_length(without '\0') [4 bytes]| interface_str | 
```

其中，每个`condition_count`会存储当前匹配的具体匹配规则，如果该规则需要额外缓冲区缓存，则会将其`buffer_offset`指向结构体后的缓冲区内，其所对应的额外信息的初始偏移位，后续反序列化只需要根据内存信息重构数据结构即可。

#### 2.3.2 Netlink 通信

`Netlink`通信模块作为全双工通信，实现内核和用户态的通信需求：
+ 增加/删除规则，用户 -> 内核
+ 获取规则详情/日志输出打印，内核 -> 用户

##### 2.3.2.1 用户态实现
用户态利用`netlink`的封装库`libnl`实现一个`netlink_tool`工具类，其可以指定通信的目标地址，并且将缓冲区数据拷贝到数据包内进行发送。

##### 2.3.2.2 内核态实现
内核态利用`netlink`封装库`genetlink`实现对用户传输的数据包的反应，即接收一个数据包，并调用对应的回调函数对数据包进行解析。

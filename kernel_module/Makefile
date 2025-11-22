# 顶层 Makefile

obj-m := myfirewall.o

# firewall.o 由多个子模块组成
myfirewall-objs := firewall.o\
                 rule/rule.o \
                 mac_filter/mac_filter.o \
                 port_filter/port_filter.o \
                 protocol_filter/ipv4_protocol.o \
				 ip_filter/ip_filter.o \

# 内核源码路径（自动获取当前内核）
KDIR := /lib/modules/$(shell uname -r)/build

# 当前目录
PWD := $(shell pwd)

# 默认目标：构建模块
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# 清理目标
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

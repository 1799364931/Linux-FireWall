# 编译器
CXX := g++
CXXFLAGS := -Wall -O2 -std=c++17 \
    -I./usr/netlink_tool \
    -I./usr/cmd_parser \
    -I./public_structs \
	-I /usr/include/libnl3
# 源文件
USR_SRCS := ./usr/firewall.cpp ./usr/cmd_parser/cmd_parser.cpp
USR_OBJS := $(USR_SRCS:.cpp=.o)

# 目标文件
USR_TARGET := usr_app

.PHONY: all usr clean

all: usr

# 编译 usr 目标
usr: $(USR_TARGET)

$(USR_TARGET): $(USR_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# 通用规则：把 .cpp 编译成 .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理
clean:
	rm -f $(USR_OBJS) $(USR_TARGET)

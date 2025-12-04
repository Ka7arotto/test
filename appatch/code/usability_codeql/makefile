# 如果是 C++ 文件，使用下面的行来代替相应的行
# SRCS := $(wildcard *.cpp)
SRCS := $(wildcard *.c)
OBJS := $(SRCS:%.c=%)
# 对于 C++，使用 g++，并且可能需要调整或添加其他编译选项
CC := gcc
CFLAGS := -Wall -g -c

# Filter out those without a main function
#MAIN_OBJS := $(foreach obj,$(OBJS),$(if $(shell grep -l 'int main' $(obj).c),$(obj)))
MAIN_OBJS := $(foreach obj,$(OBJS),$(if $(shell grep -l '{' $(obj).c),$(obj)))

all: $(MAIN_OBJS)

# 使用模式规则，对每个文件编译成独立的可执行文件，忽略失败的命令
%: %.c
	-$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS)

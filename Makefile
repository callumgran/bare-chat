# Callum Gran 2023
# See LICENSE for license info

OBJDIR = .obj
SRC = src
DIRS := $(shell find $(SRC) -type d -not -wholename "src/client")
SRCS := $(shell find $(SRC) -type f -name "*.c" -not -wholename "src/client/*")
OBJS := $(SRCS:%.c=$(OBJDIR)/%.o)

CFLAGS = -Iinclude -Wall -Wextra -Wshadow -std=c11 -g -D_POSIX_C_SOURCE=200809L
CFLAGS += -DLOGGING
LDFLAGS = -pthread
LDLIBS = -lm

.PHONY: format clean tags bear $(OBJDIR)
TARGET = server
CLIENT = client

all: $(TARGET)

$(OBJDIR)/%.o: %.c Makefile | $(OBJDIR)
	@echo [CC] $@
	@$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	@echo [LD] $@
	@$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJDIR):
	$(foreach dir, $(DIRS), $(shell mkdir -p $(OBJDIR)/$(dir)))

debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

client:
	$(CC) $(CFLAGS) -o $(CLIENT) src/client/chat_client.c src/lib/env_parser.c src/lib/queue.c src/lib/threadpool.c src/client/client.c src/chatp2p/address_book.c src/chatp2p/chat_msg.c

clean:
	rm -rf $(OBJDIR) $(TARGET) $(CLIENT)

tags:
	@ctags -R

bear:
	@bear -- make

format:
	python format.py

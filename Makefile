CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = -lncurses

SRCS = $(wildcard src/*.c)

BIN_DIR = build
OBJ_DIR = obj
$(shell mkdir -p $(BIN_DIR) $(OBJ_DIR))

OBJS = $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/wifi_monitor

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

run:
	sudo ./$(TARGET) wlx9cefd5fcd6a8 

.PHONY: all clean

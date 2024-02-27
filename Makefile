CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = -lncurses

# Use wildcard to find all .c files in src folder
SRCS = $(wildcard src/*.c)

# Create bin and obj directories if they don't exist
BIN_DIR = build
OBJ_DIR = obj
$(shell mkdir -p $(BIN_DIR) $(OBJ_DIR))

# Corresponding object files
OBJS = $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Name of the final executable
TARGET = $(BIN_DIR)/wifi_monitor

all: $(TARGET)
	sudo ./$(TARGET) wlx9cefd5fcd6a8

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean

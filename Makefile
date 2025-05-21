# Компилятор и флаги компиляции
CC ?= gcc
CFLAGS ?= -O2 -Wall -pthread -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -fsanitize=address
LDFLAGS ?= -pthread
LDLIBS ?= -lpcap -lndpi -lsqlite3

# Структура каталогов
SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj
DB_DIR := data

# Файлы исходников
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET := elbrus-dpi

# Правила сборки
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(DB_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(DB_DIR)

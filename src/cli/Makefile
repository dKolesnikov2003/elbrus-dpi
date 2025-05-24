# Makefile в папке src/cli/

# Компилятор и флаги
CC       ?= gcc
CFLAGS   ?= -O2 -Wall -pthread -std=c11 \
            -D_DEFAULT_SOURCE -D_GNU_SOURCE -fsanitize=address \
            -I$(INC_DIR)
LDFLAGS  ?= -pthread
LDLIBS   ?= -lpcap -lndpi -lsqlite3

# Директории
CORE_DIR := ../core
INC_DIR  := ../../include
OBJ_DIR  := obj

# Исходники
CLI_SRC   := elbrus_dpi.c
CORE_SRCS := $(wildcard $(CORE_DIR)/*.c)

# Объекты
CLI_OBJ   := $(OBJ_DIR)/elbrus_dpi.o
CORE_OBJS := $(patsubst $(CORE_DIR)/%.c,$(OBJ_DIR)/%.o,$(CORE_SRCS))
OBJS      := $(CLI_OBJ) $(CORE_OBJS)

# Итоговый бинарник
TARGET := elbrus-dpi

.PHONY: all clean

all: $(TARGET)

# Линковка
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# Компиляция CLI-исходника
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Компиляция модулей ядра
$(OBJ_DIR)/%.o: $(CORE_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

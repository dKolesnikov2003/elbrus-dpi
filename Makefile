CC      ?= gcc
CFLAGS  ?= -O2 -Wall -pthread -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE \
           -fsanitize=address -fPIC -Iinclude
LDFLAGS ?= -pthread -fsanitize=address
LDLIBS  ?= -lpcap -lndpi -lsqlite3

# ── Каталоги ────────────────────────────────────────────────────────────────────
SRC_DIR_CORE := src/core
SRC_DIR_CLI  := src/cli

OBJ_DIR      := obj
OBJ_DIR_CORE := $(OBJ_DIR)/core
OBJ_DIR_CLI  := $(OBJ_DIR)/cli

LIB_DIR      := lib
BIN_DIR      := bin

# ── Файлы исходников / целей ───────────────────────────────────────────────────
CORE_SRCS := $(wildcard $(SRC_DIR_CORE)/*.c)
CORE_OBJS := $(patsubst $(SRC_DIR_CORE)/%.c,$(OBJ_DIR_CORE)/%.o,$(CORE_SRCS))

CLI_SRC  := $(SRC_DIR_CLI)/el_dpi_cli.c
CLI_OBJ  := $(OBJ_DIR_CLI)/el_dpi_cli.o

LIB_TARGET := $(LIB_DIR)/libelbrus_dpi_api.so
CLI_TARGET := $(BIN_DIR)/el_dpi_cli

# ── Правила ────────────────────────────────────────────────────────────────────
.PHONY: all library cli clean
all: library cli
library: $(LIB_TARGET)

# Библиотека ──────
LIB_TARGET := $(LIB_DIR)/libelbrus_dpi_api.so

$(LIB_TARGET): $(CORE_OBJS) | $(LIB_DIR)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(LIB_DIR):
	mkdir -p $@

# CLI-утилита ─────
cli: $(CLI_TARGET)

$(CLI_TARGET): $(CLI_OBJ) $(LIB_TARGET) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $< -L$(LIB_DIR) -lelbrus_dpi_api $(LDLIBS) \
	    -Wl,-rpath,'$$ORIGIN/../$(LIB_DIR)'

# Компиляция .c → .o (core + cli) ─────
$(OBJ_DIR_CORE)/%.o: $(SRC_DIR_CORE)/%.c | $(OBJ_DIR_CORE)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR_CLI)/%.o: $(SRC_DIR_CLI)/%.c | $(OBJ_DIR_CLI)
	$(CC) $(CFLAGS) -c $< -o $@

# ── Автоматическое создание нужных директорий ──────────────────────────────────
$(OBJ_DIR_CORE) $(OBJ_DIR_CLI) $(BIN_DIR):
	mkdir -p $@

# ── Очистка ────────────────────────────────────────────────────────────────────
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

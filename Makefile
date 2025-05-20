# Компилятор и флаги компиляции
CC ?= gcc
CFLAGS ?= -O2 -Wall -pthread -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS ?= -pthread
LDLIBS ?= -lpcap -lndpi -lsqlite3

# Если используем компилятор MCST LCC (Эльбрус), можно указать оптимизацию под архитектуру:
# Пример: CFLAGS += -mtune=elbrus-8c
# (Актуальные опции уточняются в документации MCST LCC)

# Структура каталогов
SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj

# Файлы исходников
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET := ndpi_analyzer

# Правила сборки
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Top‐level Makefile

# Директории
INC_DIR   := include
SRC_DIR   := src
LIB_DIR   := lib

# Компилятор и флаги
CC        := gcc
CFLAGS    := -Wall -Wextra -O2 -std=c11 -fPIC -D_DEFAULT_SOURCE -D_GNU_SOURCE -fsanitize=address -I$(INC_DIR)
SHLDFLAGS := -shared -fPIC
LDLIBS    := -lpcap -lndpi -lsqlite3 -lpthread

# Источники и объекты
CORE_SRCS := $(wildcard $(SRC_DIR)/core/*.c)
CORE_OBJS := $(patsubst $(SRC_DIR)/core/%.c,$(SRC_DIR)/core/%.o,$(CORE_SRCS))

CLI_SRC   := $(SRC_DIR)/cli/eldpi_cli.c
CLI_OBJ   := $(SRC_DIR)/cli/eldpi_cli.o

GUI_SRC   := $(SRC_DIR)/gui/eldpi_gui.c
GUI_OBJ   := $(SRC_DIR)/gui/eldpi_gui.o

.PHONY: all clean

all: $(LIB_DIR)/libelbrus_dpi.so eldpi_cli 
#eldpi_gui

# 1) Собираем core-объекты
$(CORE_OBJS): $(SRC_DIR)/core/%.o : $(SRC_DIR)/core/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 2) Динамическая библиотека
$(LIB_DIR)/libelbrus_dpi.so: $(CORE_OBJS)
	mkdir -p $(LIB_DIR)
	$(CC) $(SHLDFLAGS) -fsanitize=address -o $@ $^ $(LDLIBS) -fsanitize=address

# 3) CLI–утилита, только с API-заголовком
eldpi_cli: $(CLI_OBJ) $(LIB_DIR)/libelbrus_dpi.so
	$(CC) -fsanitize=address -o $@ $^ -L$(LIB_DIR) -lelbrus_dpi -lpcap -lpthread -fsanitize=address


$(CLI_OBJ): $(CLI_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# 4) GUI–приложение
#eldpi_gui: $(GUI_OBJ) $(LIB_DIR)/libelbrus_dpi.so
#	$(CC) -o $@ $^ -L$(LIB_DIR) -lelbrus_dpi -lX11 -lpcap -lpthread

$(GUI_OBJ): $(GUI_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Убираем всё
clean:
	rm -rf $(CORE_OBJS) $(CLI_OBJ) $(GUI_OBJ) \
	       $(LIB_DIR)/libelbrus_dpi.so \
	       eldpi_cli eldpi_gui

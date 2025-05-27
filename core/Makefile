# Компилятор и флаги
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -pthread -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -Iinclude
LDFLAGS ?= -pthread
LDLIBS  ?= -lpcap -lndpi -lsqlite3

# Пути
SRCDIR  := src
INCDIR  := include
OBJDIR  := obj
TARGET  := libelbrus-dpi.a

# Все .c файлы из src/
SRC     := $(wildcard $(SRCDIR)/*.c)
OBJ     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# Цели
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	@mkdir -p $(HOME)/.local/share/elbrus-dpi/
	$(AR) rcs $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

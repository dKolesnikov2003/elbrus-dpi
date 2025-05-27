# Компилятор и флаги
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -pthread -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -I../core/include
LDFLAGS ?= -pthread
LDLIBS  ?= ../core/libelbrus-dpi.a -lpcap -lndpi -lsqlite3

# Пути
SRCDIR  := src
OBJDIR  := obj
TARGET  := el-dpi-cli

# Исходный и объектный файл
SRC     := $(SRCDIR)/el_dpi_cli.c
OBJ     := $(OBJDIR)/el_dpi_cli.o

# Цели
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

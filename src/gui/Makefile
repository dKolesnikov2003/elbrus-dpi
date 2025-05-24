CC      := gcc
RM      := rm -f
CFLAGS  := -I../../include -Wall -Wextra -O2
LDFLAGS := -L../../lib -lelbrus_dpi
LIBS    := -lX11 -lpcap -lpthread

SRC := eldpi_gui.c
OBJ := $(SRC:.c=.o)
BIN := eldpi_gui

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ) $(BIN)
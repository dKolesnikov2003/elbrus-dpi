CC      := gcc
RM      := rm -f
CFLAGS  := -I../../include -Wall -Wextra -O2 -fPIC

SRC := capture.c db_writer.c elbrus_dpi_api.c packet_processor.c
OBJ := $(SRC:.c=.o)

all: $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ)
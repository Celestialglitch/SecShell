CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11
TARGET  = secshell
SRC     = secshell.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) secshell_audit.log

.PHONY: all clean

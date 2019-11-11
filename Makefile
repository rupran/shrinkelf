CC = gcc
LIB = -L libelf -l elf

all: shrinkelf

clean:
	rm -f shrinkelf

.PHONY: all clean



shrinkelf: main.c
	$(CC) $^ -o $@ $(LIB)


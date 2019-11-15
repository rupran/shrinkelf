CC = gcc
LIB = -L libelf -l elf
DEBUG = -ggdb -g3
FLAGS = -Wall -Wextra

all: shrinkelf

clean:
	rm -f shrinkelf

debug: main.c
	$(CC) $^ -o shrinkelf $(LIB) $(DEBUG) $(FLAGS)


.PHONY: all clean debug



shrinkelf: main.c
	$(CC) $^ -o $@ $(LIB) $(FLAGS)


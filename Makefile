CC = gcc
LIB = -L libelf -l elf -I libelf
DEBUG = -ggdb -g3
FLAGS = -Wall -Wextra

all: shrinkelf

clean:
	rm -f shrinkelf
	rm -f cmdline.*
	rm -f *.o

debug: main.c cmdline.o
	$(CC) -c $< $(LIB) $(DEBUG) $(FLAGS)
	$(CC) -o shrinkelf cmdline.o $(patsubst %.c, %.o, $<) $(LIB) $(DEBUG) $(FLAGS)


.PHONY: all clean debug


cmdline.o: shrinkelf.ggo
	gengetopt < shrinkelf.ggo
	$(CC) -c $(patsubst %.o, %.c, $@)

shrinkelf: main.c cmdline.o
	$(CC) -c $< $(LIB) $(FLAGS)
	$(CC) -o $@ cmdline.o $(patsubst %.c, %.o, $<) $(LIB) $(FLAGS)


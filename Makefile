UNAME := $(shell uname)

RTFLAGS=-lrt
ifeq ($(UNAME), Darwin)
RTFLAGS=-framework CoreServices
endif
CFLAGS=-Wall -O3 -I libuv/include -DNDEBUG -std=gnu99
FILES=server.c utils.c encrypt.c md5.c
APP=server

all: $(FILES) libuv/libuv.a
	$(CC) $(CFLAGS) $(RTFLAGS) -lm -o \
	$(APP) $(FILES) \
	libuv/libuv.a -lpthread

libuv/libuv.a:
	$(MAKE) -C libuv

valgrind: CFLAGS=-Wall -O0 -I libuv/include -g -std=gnu99
valgrind: all
	valgrind --leak-check=full ./server

debug: CFLAGS=-Wall -O0 -I libuv/include -g -std=gnu99
debug: all

clean:
	$(MAKE) -C libuv clean
	rm -f server
	rm -rf *.dSYM

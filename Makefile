UNAME := $(shell uname)

RTFLAGS=-lrt
ifeq ($(UNAME), Darwin)
RTFLAGS=-framework CoreServices
endif
OLEVEL=-O3 -DNDEBUG
CFLAGS=-Wall $(OLEVEL) -I libuv/include -std=gnu99
FILES=server.c utils.c encrypt.c md5.c rc4.c
APP=server

all: $(FILES) libuv/libuv.a
	$(CC) $(CFLAGS) -o \
	$(APP) $(FILES) \
	libuv/libuv.a -lpthread -lcrypto -lm $(RTFLAGS)

libuv/libuv.a:
	$(MAKE) -C libuv

valgrind: OLEVEL=-O0 -g
valgrind: all
	valgrind --leak-check=full ./server

debug: OLEVEL=-O0 -g
debug: all

gprof: OLEVEL=-O0 -g -pg
gprof: all

test: OLEVEL=-O0 -g
test: FILES=tests.c encrypt.c md5.c rc4.c
test: APP=test
test: all
	./test
	cd pytest; python test.py

clean:
	$(MAKE) -C libuv clean
	rm -f server
	rm -rf *.dSYM
	rm -rf test

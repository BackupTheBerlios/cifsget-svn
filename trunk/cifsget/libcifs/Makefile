SRCS=transport.c proto.c transact.c find.c rap.c debug.c codepage.c buffer.c
OBJS=$(SRCS:.c=.o)
CFLAGS=-g -std=c99 -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LIBNAME=libcifs.a

all: ${LIBNAME}

.c.o:
	${CC} -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o *.a *~

distclean: clean
	rm -f .depends

.depends: includes.h
	${CC} -MM ${CFLAGS} $(SRCS) 1> $@

$(LIBNAME): $(OBJS)
	ar r $@ $^
	ranlib $@

include .depends


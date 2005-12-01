CFLAGS=-g -std=c99 -Wall
OBJECTS=transport.o proto.o codepage.o uri.o transact.o find.o rap.o flow.o
PREFIX=${HOME}

ifdef WINDOWS
	CC=i586-mingw32msvc-gcc
	CFLAGS+=-DWINDOWS
	LDFLAGS+=-lwsock32
	SUFFIX=.exe
endif

OBJECTS+=debug.o

ifdef DEBUG
	CFLAGS+=-DDEBUG
endif

TARGET=cifsget${SUFFIX}

all: ${TARGET}

install: all
	cp ${TARGET} ${PREFIX}/bin/

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

struct.h: struct.sgs sgs
	./sgs < $< > $@

${TARGET}: cifsget.o ${OBJECTS}
	${CC} -o $@ $^ ${LDFLAGS}
	
clean:
	rm -f *.o ${TARGET} tags fusesmb .depends

.depends: *.c *.h
	${CC} ${CFLAGS} -M *.c > $@

dist: clean
	cd .. ;	tar czf "cifsget_`date +%Y-%m-%d_%H%M`.tgz" cifsget

fusesmb: transport.o proto.o transact.o debug.o find.o rap.o fusesmb.o uri.o codepage.o
	${CC} -o $@ $^ ${LDFLAGS} -lfuse
	
include .depends


CFLAGS=-g -std=c99 -Wall
OBJECTS=transport.o proto.o codepage.o uri.o transact.o find.o rap.o flow.o mirror.o human.o debug.o
PREFIX=${HOME}

ifdef WINDOWS
	CC=i586-mingw32msvc-gcc
	CFLAGS+=-DWINDOWS
	LDFLAGS+=-lwsock32
	SFX=.exe
endif

all: cifsget

install: all
	cp cifsget ${PREFIX}/bin/

.c.o: 
	${CC} ${CFLAGS} -c -o $@ $<

struct.h: struct.sgs sgs
	./sgs < $< > $@

cifsget: cifsget.o ${OBJECTS}
	${CC} -o $@ $^ ${LDFLAGS}

cifsmirror: cifsmirror.o ${OBJECTS}
	${CC} -o $@ $^ ${LDFLAGS}
	
clean:
	rm -f *.o cifsmirror cifsget tags fusesmb

distclean: clean
	rm -f .depends

.depends: includes.h
	${CC} ${CFLAGS} -M *.c > $@

dist: distclean
	cd .. ;	tar czf "cifsget_`date +%Y-%m-%d_%H%M`.tgz" cifsget

fusesmb: transport.o proto.o transact.o debug.o find.o rap.o fusesmb.o uri.o codepage.o
	${CC} -o $@ $^ ${LDFLAGS} -lfuse
	
include .depends


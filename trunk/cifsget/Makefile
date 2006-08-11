CFLAGS=-g -std=c99 -Wall
OBJECTS=flow.o mirror.o human.o uri.o libcifs/libcifs.a
PREFIX=${HOME}

all: libs cifsget

libs:
	make -C libcifs

install: all
	cp cifsget ${PREFIX}/bin/

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

cifsget: cifsget.o ${OBJECTS}
	${CC} -o $@ $^ ${LDFLAGS}

cifsmirror: cifsmirror.o ${OBJECTS}
	${CC} -o $@ $^ ${LDFLAGS}

clean:
	rm -f *.o cifsmirror cifsget tags fusesmb
	make -C libcifs clean

distclean: clean
	rm -f .depends
	make -C libcifs distclean

dist: distclean
	cd .. ;	tar czf "cifsget_`date +%Y-%m-%d_%H%M`.tgz" cifsget

fusesmb: transport.o proto.o transact.o debug.o find.o rap.o fusesmb.o uri.o codepage.o
	${CC} -o $@ $^ ${LDFLAGS} -lfuse


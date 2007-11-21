CFLAGS=-Os -g -std=c99 -Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS=-Llibcifs
SRCS=flow.c human.c uri.c cifsget.c fusecifs.c
PREFIX=${HOME}

all: libs cifsget

libs:
	make -C libcifs

install: all
	install cifsget ${PREFIX}/bin/

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

cifsget: cifsget.o flow.o human.o uri.o libcifs/libcifs.a
	$(CC) -o $@ $^ -lcifs $(LDFLAGS)
	
cifs_spider: cifs_spider.o uri.o libcifs/libcifs.a
	$(CC) -o $@ $^ -lcifs $(LDFLAGS)

fusecifs: fusecifs.o
	${CC} -o $@ $^ -lfuse -lcifs ${LDFLAGS}

clean:
	rm -f *.o cifsmirror cifsget tags fusecifs
	make -C libcifs clean

distclean: clean
	rm -f .depends
	make -C libcifs distclean

dist: distclean
	cd .. ;	tar czf "cifsget_`date +%Y-%m-%d_%H%M`.tgz" cifsget

dep .depends:
	$(CC) -MM $(CFLAGS) $(SRCS) 1> .depends

include .depends


#include ./stdmk

CC = gcc

CFLAGS = -DDEBUG -DHAVE_STAT -g -O2 -w -D_REENTRANT -DTHREAD -DPTHREADS  \
               -I/usr/include -I/usr/local/include \
	-I/usr/include/mysql  -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m32 -fasynchronous-unwind-tables -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -fno-strict-aliasing -fwrapv -fPIC   -DUNIV_LINUX -DUNIV_LINUX

LIB1=/usr/lib/

LIB2=/usr/local/lib/

LIBDIR_MYSQL=/usr/lib/mysql/

OBJS=mhf.o http.o buffer.o

#$(CC) ${CFLAGS} -o mhf.x mhf.o http.o -L$(LIB1) -L$(LIB2) -L$(LIBDIR_MYSQL) -lpthread -levent -lgd -lmysqlclient -lmemcached -ldb -lpcre

all:	${OBJS}
	$(CC) ${CFLAGS} -o mhf.x mhf.o http.o buffer.o -L$(LIB1) -L$(LIB2) -lpthread
	echo OK!! 

mhf.o:mhf.c mhf.h
		${CC} ${CFLAGS} -c mhf.c

http.o:http.c mhf.h
		${CC} ${CFLAGS} -c http.c

buffer.o:buffer.c mhf.h
		${CC} ${CFLAGS} -c buffer.c

clean:
		rm -f *.o
		rm -f *.x
		rm -f *.a


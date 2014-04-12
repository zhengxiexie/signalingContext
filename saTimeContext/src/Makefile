CC      = gcc44
CFLAGS  = -O2 -m64 -g -D_THREAD_SAFE_ -D_REENTRANT_ -Werror -Wall
LDFLAGS = -O2 -m64 -g -lpthread

OBJECTS = config.o context.o reader-thread.o main.o comsumer-thread.o log.o

.PHONY: clean all

all:: $(OBJECTS)
	$(CC) $(LDFLAGS) -o saTimeContext $(OBJECTS)
	-mkdir -p ../bin
	mv saTimeContext ../bin

config.o: config.c config.h log.h
	$(CC) $(CFLAGS) -c -o $@ config.c

context.o: context.c config.h context.h log.h reader-thread.h
	$(CC) $(CFLAGS) -c -o $@ context.c

reader-thread.o: reader-thread.c reader-thread.h context.h comsumer-thread.h config.h log.h
	$(CC) $(CFLAGS) -c -o $@ reader-thread.c

comsumer-thread.o: comsumer-thread.c comsumer-thread.h context.h config.h log.h
	$(CC) $(CFLAGS) -c -o $@ comsumer-thread.c

main.o: main.c comsumer-thread.h context.h config.h log.h reader-thread.h
	$(CC) $(CFLAGS) -c -o $@ main.c

log.o: log.c log.h
	$(CC) $(CFLAGS) -c -o $@ log.c

install:: all
	cp ../bin/saTimeContext ../../../../bin/c

clean:
	-rm -f *.o ../bin/*


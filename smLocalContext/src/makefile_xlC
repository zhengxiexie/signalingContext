#DEBUG  = -g
CC      = xlC
INCLUDE = -I ../include 
LIBS    = -lpthread
OBJECTS = sspublic.o ssnet.o sscontext.o ssanalyze.o
LDFLAGS = -O2 -q64 $(LIBS) -lm
CFLAGS  = -O2 -q64 -D_THREAD_SAFE $(DEBUG) $(INCLUDE)

all::  smLocalContext
	rm -f ../bin/smLocalContext
	cp smLocalContext ../bin/
	rm -f *.o smLocalContext

ssnet.o:  ssnet.cpp
	$(CC) $(CFLAGS) -c -o $@ ssnet.cpp

sscontext.o:  sscontext.cpp
	$(CC) $(CFLAGS) -c -o $@ sscontext.cpp

sspublic.o:  sspublic.cpp
	$(CC) $(CFLAGS) -c -o $@ sspublic.cpp

ssanalyze.o:  ssanalyze.cpp
	$(CC) $(CFLAGS) -c -o $@ ssanalyze.cpp

smLocalContext:  $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

clean:
	-rm -f $(OBJECTS)

install: all
	-rm -f ../../../../bin/c/smLocalContext
	cp ../bin/smLocalContext ../../../../bin/c/smLocalContext

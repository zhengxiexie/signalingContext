#UID=aimdata
#PWD=aimd0717
#DB=CRMNEW77
UID=db2inst1
PWD=db2inst1
DB=bass20
DEBUG=-g

RM=rm -f

DB2PATH = /bi/db2v91/sqllib
#DB2PATH = /home/db2inst1/sqllib

CC = /usr/bin/xlc
CFLAGS= -I$(DB2PATH)/include -lthread -q64 $(DEBUG) -I ../include
#CFLAGS= -I/data/crmtest/ler_db2/usr/opt/db2_08_01/include64/ -lthread -q64 $(DEBUG) -I ../include

LINKOPTS = -bloadmap:loadmap
LINKLIBS = -lpthread -L$(DB2PATH)/lib -ldb2 -lC
OBJECTS = sspublic.o sscontext.o ssanalyze.o ssdb2.o utilemb.o ssnet.o


all::  saRoamMonitor
	rm -f ../bin/saRoamMonitor
	cp saRoamMonitor ../bin
	rm -f *.o saRoamMonitor stcp
	
ssnet.o:  ssnet.cpp
	$(CC) -c ssnet.cpp ${CFLAGS}

sscontext.o:  sscontext.cpp 
	$(CC) -c sscontext.cpp ${CFLAGS}

sspublic.o:  sspublic.cpp 
	$(CC) -c sspublic.cpp ${CFLAGS}

ssanalyze.o:  ssanalyze.cpp 
	$(CC) -c ssanalyze.cpp ${CFLAGS}

utilemb.o:  utilemb.C
	$(CC) -o utilemb.o -cpp $(CFLAGS) utilemb.C

ssdb2.o:  ssdb2.C
	$(CC) -o ssdb2.o -c $(CFLAGS) ssdb2.C

utilemb.C : utilemb.sqC
	db2 connect to $(DB) user $(UID) using $(PWD);\
	db2 prep utilemb.sqC bindfile;\
	db2 bind utilemb.bnd;\
	db2 connect reset;\
	db2 terminate;\

ssdb2.C : ssdb2.sqC
	db2 connect to $(DB) user $(UID) using $(PWD);\
	db2 prep ssdb2.sqC bindfile;\
	db2 bind ssdb2.bnd;\
	db2 connect reset;\
	db2 terminate;\

## 信令分析主程序 ###############################################
saRoamMonitor:  $(OBJECTS)
	$(CC) $(LINKOPTS) $(LINKLIBS) -o $@ $(OBJECTS) $(CFLAGS) $(LIBS)

clean:
	@$(RM) $(OBJECTS) ssdispatch.o dispatch ssdb2.C utilemb.C *.bnd *.C loadmap nohup.out
install:
	@$(RM) ../../../bin/saRoam*
	@$(RM) ../../../etc/saRoam*
	cp ../bin/* ../../../bin/
	cp ../etc/* ../../../etc/

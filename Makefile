LIBNAME = ./bin/dns_sift.so
EXEC_NAME = ./bin/dns_sift
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c src/dns/*.c))
CFLAGS = -gdwarf-2 -O3 -Wall
LDFLAGS = -L/usr/local/lib -shared -rdynamic -Wl,-soname,$(LIBNAME) -Wl,--no-undefined 
LDLIBS = -lnfnetlink -lnetfilter_queue -lpthread -lpcap

app : $(OBJECTS)
	mkdir -p bin
	$(MAKE) -C src/classifier
	$(CC) $(OBJECTS) src/classifier/classifier_interface.o -o $(EXEC_NAME) $(LDLIBS) $(CFLAGS)	
	
build : $(OBJECTS)
	$(CC) $(OBJECTS) -o $(LIBNAME) $(LDFLAGS) $(LDLIBS)
	
clean :
	rm -rf $(EXEC_NAME) $(LIB_NAME) *.o *~ src/dns/*.o src/dns/*~ bin
	$(MAKE) -C src/classifier clean
.PHONY: clean


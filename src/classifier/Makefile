CC=gcc
CFLAGS=-I/usr/include/python2.7
LDFLAGS=-lpython2.7 -shared -rdynamic -Wl,-soname
default: classifier_C_interface.py
	python classifier_C_interface.py
	$(CC) $(CFLAGS) $(LDFLAGS) c_interface.c -o classifier_interface.o
	
clean:
	rm -f *.o *~

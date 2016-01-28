CC=gcc
CFLAGS=-I/usr/include/python2.7
LDFLAGS=-lpython2.7 -shared -rdynamic -Wl,-soname
default: classifier.py
	$(CC) $(CFLAGS) $(LDFLAGS) -c c_interface.c -o classifier_interface.o
	
clean:
	rm -f *.o *~ *.pyc

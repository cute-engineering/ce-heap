all: libheap.so libheap.a

libheap.so: libheap.o
	$(CC) -shared -fPIC -o $@ $^ $(CFLAGS)

libheap.a: libheap.o
	$(AR) rcs $@ $^ 

clean:
	rm -f *.o *.so *.a

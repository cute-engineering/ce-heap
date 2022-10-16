#!/bin/sh
# build libheap.so
gcc -shared -fPIC -o libheap.so libheap.c posix.c
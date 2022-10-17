#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "libheap.h"

void *heap_hook_alloc_block(void *ctx, size_t size) {
  (void)ctx;
  return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
              -1, 0);
}

void heap_hook_free_block(void *ctx, void *ptr, size_t size) {
  (void)ctx;
  munmap(ptr, size);
}

void heap_hook_error(void *ctx, const char *msg) {
  (void)ctx;
  fprintf(stderr, "heap: %s\n", msg);
}

struct Heap _heap = {
    .alloc = heap_hook_alloc_block,
    .free = heap_hook_free_block,
    .error = heap_hook_error,
};

void *malloc(size_t size) { return heap_alloc(&_heap, size); }

void free(void *ptr) { heap_free(&_heap, ptr); }

void *calloc(size_t nmemb, size_t size) {
  return heap_calloc(&_heap, nmemb, size);
}

void *realloc(void *ptr, size_t size) {
  return heap_realloc(&_heap, ptr, size);
}
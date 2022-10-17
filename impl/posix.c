#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

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
  write(2, msg, strlen(msg));
  write(2, "\n", 1);
}

struct Heap _heap = {
    .alloc = heap_hook_alloc_block,
    .free = heap_hook_free_block,
    .error = heap_hook_error,
};

// lock for heap
static pthread_mutex_t _heap_lock = PTHREAD_MUTEX_INITIALIZER;

void *malloc(size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_alloc(&_heap, size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}

void free(void *ptr) {
  pthread_mutex_lock(&_heap_lock);
  heap_free(&_heap, ptr);
  pthread_mutex_unlock(&_heap_lock);
}

void *calloc(size_t nmemb, size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_calloc(&_heap, nmemb, size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}

void *realloc(void *ptr, size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_realloc(&_heap, ptr, size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}
#include <pthread.h>

#include "impl.h"

// lock for heap
static bool _heap_init = false;
static pthread_mutex_t _heap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct Heap _heap_impl = {0};

static struct Heap *ensure_heap(void) {
  if (!_heap_init) {
    _heap_impl = heap_impl();
    _heap_init = true;
  }
  return &_heap_impl;
}

void *malloc(size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_alloc(ensure_heap(), size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}

void free(void *ptr) {
  pthread_mutex_lock(&_heap_lock);
  heap_free(ensure_heap(), ptr);
  pthread_mutex_unlock(&_heap_lock);
}

void *calloc(size_t nmemb, size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_calloc(ensure_heap(), nmemb, size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}

void *realloc(void *ptr, size_t size) {
  pthread_mutex_lock(&_heap_lock);
  void *res = heap_realloc(ensure_heap(), ptr, size);
  pthread_mutex_unlock(&_heap_lock);
  return res;
}

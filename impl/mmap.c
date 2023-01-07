#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libheap.h"

static void *alloc_block(void *ctx, size_t size) {
  (void)ctx;
  return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
              -1, 0);
}

static void free_block(void *ctx, void *ptr, size_t size) {
  (void)ctx;
  munmap(ptr, size);
}

static void hook_log(void *ctx, enum HeapLogType type, const char *msg,
                     va_list args) {
  (void)ctx;
  char buf[256];
  int len = vsnprintf(buf, sizeof(buf), msg, args);
  if (type == HEAP_ERROR) {
    write(1, "libheap: error: ", 16);
  } else {
    write(1, "libheap: trace: ", 16);
  }

  write(1, buf, len);
  write(2, "\n", 1);
}

struct Heap heap_impl(void) {
  return (struct Heap){
      .alloc = alloc_block,
      .free = free_block,
      .log = hook_log,
  };
}

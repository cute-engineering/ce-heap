#ifndef LIBHEAP_H
#define LIBHEAP_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HEAP_MAGIC 0xc0c0c0c0c0c0c0c0
#define HEAP_DEAD 0xdeaddeaddeaddead
#define HEAP_ALIGN (64)
#define HEAP_PAGE_SIZE (4096)
#define HEAP_MIN_REQU (4096 * 4)
#define HEAP_ALIGNED(X) (((X) + (HEAP_ALIGN - 1)) & ~(HEAP_ALIGN - 1))
#define HEAP_PAGE_ALIGNED(X)                                                   \
  (((X) + (HEAP_PAGE_SIZE - 1)) & ~(HEAP_PAGE_SIZE - 1))

struct HeapNode {
  union {
    uint64_t magic;
    uint8_t m[8];
  };
  struct HeapNode *prev;
  struct HeapNode *next;
};

#define HEAP_NODE(T)                                                           \
  union {                                                                      \
    struct HeapNode base;                                                      \
    struct {                                                                   \
      uint64_t magic;                                                          \
      T *prev;                                                                 \
      T *next;                                                                 \
    };                                                                         \
  }

struct HeapMajor {
  HEAP_NODE(struct HeapMajor);

  size_t size;
  size_t used;
  struct HeapMinor *minor;
};

struct HeapMinor {
  HEAP_NODE(struct HeapMinor);

  size_t size;
  size_t used;
  struct HeapMajor *major;
};

typedef void *HeapAllocBlockFn(void *ctx, size_t size);

typedef void HeapFreeBlockFn(void *ctx, void *ptr, size_t size);

enum HeapLogType {
  HEAP_TRACE,
  HEAP_ERROR,
};

typedef void HeapLogFn(void *ctx, enum HeapLogType type, const char *fmt,
                       va_list args);

struct Heap {
  void *ctx;
  HeapAllocBlockFn *alloc;
  HeapFreeBlockFn *free;
  HeapLogFn *log;

  struct HeapMajor *root;
  struct HeapMajor *best;
};

/* ---- Internal functions -------------------------------------------------- */

/* Heap hook functions */

void *heap_alloc_block(struct Heap *heap, size_t size);

void heap_free_block(struct Heap *heap, void *ptr, size_t size);

void heap_trace(struct Heap *heap, const char *msg, ...);

void heap_error(struct Heap *heap, const char *msg, ...);

/* Heap node functions */

bool heap_node_check(struct Heap *heap, struct HeapNode *node);

void heap_node_append(struct HeapNode *node, struct HeapNode *other);

void heap_node_prepend(struct HeapNode *node, struct HeapNode *other);

void heap_node_remove(struct HeapNode *node);

/* Heap major functions */

size_t heap_major_avail(struct HeapMajor *maj);

struct HeapMajor *heap_major_create(struct Heap *heap, size_t size);

struct HeapMinor *heap_major_alloc(struct Heap *heap, struct HeapMajor *maj,
                                   size_t size);

void heap_major_free(struct Heap *heap, struct HeapMajor *maj);

/* Heap minor functions */

size_t heap_minor_avail(struct HeapMinor *min);

struct HeapMinor *heap_minor_create(struct HeapMajor *maj, size_t size);

struct HeapMinor *heap_minor_split(struct HeapMinor *min, size_t size);

void heap_minor_free(struct Heap *heap, struct HeapMinor *min);

void heap_minor_resize(struct HeapMinor *min, size_t size);

struct HeapMinor *heap_minor_from(void *ptr);

void *heap_minor_to(struct HeapMinor *min);

/* ---- Public functions ---------------------------------------------------- */

void *heap_alloc(struct Heap *heap, size_t size);

void *heap_realloc(struct Heap *heap, void *ptr, size_t size);

void *heap_calloc(struct Heap *heap, size_t num, size_t size);

void heap_free(struct Heap *heap, void *ptr);

#endif

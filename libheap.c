#include "libheap.h"

/* Heap hook functions */

void *heap_alloc_block(struct Heap *heap, size_t size) {
  return heap->alloc(heap->ctx, size);
}

void heap_free_block(struct Heap *heap, void *ptr, size_t size) {
  heap->free(heap->ctx, ptr, size);
}

void heap_trace(struct Heap *heap, const char *msg, ...) {
  va_list args;
  va_start(args, msg);
  heap->log(heap->ctx, HEAP_TRACE, msg, args);
  va_end(args);
}

void heap_error(struct Heap *heap, const char *msg, ...) {
  va_list args;
  va_start(args, msg);
  heap->log(heap->ctx, HEAP_ERROR, msg, args);
  va_end(args);
}

/* Heap node functions */

bool heap_node_check(struct Heap *heap, struct HeapNode *node) {
  size_t overflow = 0, i = 0;

  if (node->magic == HEAP_MAGIC)
    return true;

  if (node->magic == HEAP_DEAD) {
    heap_error(heap, "heap double free detected");
    return false;
  }

  for (i = 0; i < sizeof(node->magic); i++) {
    if (node->m[i] != 0xc0)
      overflow++;
  }

  if (overflow == sizeof(node->magic))
    heap_error(heap, "heap corruption/use-after-free detected");
  else
    heap_error(heap, "heap overflow detected");

  return false;
}

void heap_node_append(struct HeapNode *list, struct HeapNode *node) {
  node->prev = list;
  node->next = list->next;
  if (list->next) {
    list->next->prev = node;
  }
  list->next = node;
}

void heap_node_prepend(struct HeapNode *list, struct HeapNode *node) {
  node->next = list;
  node->prev = list->prev;
  if (list->prev) {
    list->prev->next = node;
  }
  list->prev = node;
}

void heap_node_remove(struct HeapNode *node) {
  if (node->prev) {
    node->prev->next = node->next;
  }

  if (node->next) {
    node->next->prev = node->prev;
  }

  node->prev = NULL;
  node->next = NULL;
}

/* Heap major functions */

size_t heap_major_avail(struct HeapMajor *maj) { return maj->size - maj->used; }

struct HeapMajor *heap_major_create(struct Heap *heap, size_t size) {
  size = size + HEAP_ALIGN;
  size = size < HEAP_MIN_REQU ? HEAP_MIN_REQU : size;
  size = HEAP_PAGE_ALIGNED(size);

  struct HeapMajor *maj = (struct HeapMajor *)heap_alloc_block(heap, size);
  *maj = (struct HeapMajor){
      .magic = HEAP_MAGIC,
      .size = size,
      .used = HEAP_ALIGN,
  };

  return maj;
}

struct HeapMinor *heap_major_alloc(struct Heap *heap, struct HeapMajor *maj,
                                   size_t size) {
  struct HeapMinor *min = maj->minor;

  while (min) {
    if (!min->used && heap_minor_avail(min) >= size) {
      heap_trace(heap, "heap minor is unused and big enough, reusing");
      heap_minor_resize(min, size);
      return min;
    }

    if (min->used && heap_minor_avail(min) >= size + HEAP_ALIGN) {
      heap_trace(heap, "heap minor is used but big enough, splitting");
      return heap_minor_split(min, size);
    }

    min = min->next;
  }

  return NULL;
}

void heap_major_free(struct Heap *heap, struct HeapMajor *maj) {
  struct HeapMajor *next = maj->next;

  heap_node_remove(&maj->base);
  heap_free_block(heap, maj, maj->size);

  if (heap->root == maj)
    heap->root = next;

  if (heap->best == maj)
    heap->best = NULL;
}

/* Heap minor functions */

size_t heap_minor_avail(struct HeapMinor *min) { return min->size - min->used; }

struct HeapMinor *heap_minor_create(struct HeapMajor *maj, size_t size) {
  struct HeapMinor *min = (struct HeapMinor *)((uintptr_t)maj + HEAP_ALIGN);

  *min = (struct HeapMinor){
      .magic = HEAP_MAGIC,
      .size = heap_major_avail(maj) - HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  maj->used += size + HEAP_ALIGN;
  maj->minor = min;

  return min;
}

struct HeapMinor *heap_minor_split(struct HeapMinor *min, size_t size) {
  struct HeapMajor *maj = min->major;
  struct HeapMinor *newMin =
      (struct HeapMinor *)((uintptr_t)min + HEAP_ALIGN + min->used);

  *newMin = (struct HeapMinor){
      .magic = HEAP_MAGIC,
      .size = heap_minor_avail(min) - HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  min->size = min->used;
  maj->used += HEAP_ALIGN + size;
  heap_node_append(&min->base, &newMin->base);

  return newMin;
}

void heap_minor_free(struct Heap *heap, struct HeapMinor *min) {
  struct HeapMajor *maj = min->major;
  struct HeapMinor *prev = min->prev;
  struct HeapMinor *next = min->next;

  maj->used -= min->used;
  min->used = 0;

  if (prev) {
    heap_trace(heap, "mergin with previous minor");
    min->magic = HEAP_DEAD;
    prev->size += min->size + HEAP_ALIGN;
    maj->used -= HEAP_ALIGN;

    heap_node_remove(&min->base);
    min = prev;
  }

  if (next && !next->used) {
    heap_trace(heap, "next minor is unused, merging");
    next->magic = HEAP_DEAD;
    min->size += next->size + HEAP_ALIGN;
    maj->used -= HEAP_ALIGN;

    heap_node_remove(&next->base);
  }

  if (maj->used == HEAP_ALIGN) {
    heap_trace(heap, "major is empty, freeing");
    heap_major_free(heap, maj);
  }
}

void heap_minor_resize(struct HeapMinor *min, size_t size) {
  if (min->used > size) {
    min->major->used -= min->used - size;
  } else {
    min->major->used += size - min->used;
  }
  min->used = size;
}

struct HeapMinor *heap_minor_from(void *ptr) {
  return (struct HeapMinor *)((uintptr_t)ptr - HEAP_ALIGN);
}

void *heap_minor_to(struct HeapMinor *min) {
  return (void *)((uintptr_t)min + HEAP_ALIGN);
}

/* Heap functions */

void *heap_alloc(struct Heap *heap, size_t size) {
  struct HeapMajor *maj;
  struct HeapMinor *min;

  heap_trace(heap, "allocating %zu bytes", size);

  size = HEAP_ALIGNED(size);
  if (size == 0) {
    heap_trace(heap, "done: size is 0");
    return NULL;
  }

  if (!heap->root) {
    heap_trace(heap, "no root, creating new major");
    heap->root = heap_major_create(heap, size);
    heap->best = heap->root;
    min = heap_minor_create(heap->root, size);

    heap_trace(heap, "done: created new major");
    return heap_minor_to(min);
  }

  if (!heap->best) {
    heap_trace(heap, "no best, setting to root");
    heap->best = heap->root;
  }

  if (heap_major_avail(heap->best) >= size) {
    heap_trace(heap, "best major has enough space");
    min = heap_major_alloc(heap, heap->best, size);
    if (min) {
      heap_trace(heap, "done: allocated from best major");
      return heap_minor_to(min);
    }
    heap_trace(heap, "major doesn't enough contiguous space");
  }

  maj = heap->root;

  while (maj) {
    if (heap_major_avail(maj) > heap_major_avail(heap->best)) {
      heap_trace(heap, "found better major");
      heap->best = maj;
    }

    if (heap_major_avail(maj) >= size) {
      heap_trace(heap, "found major with enough space");
      min = heap_major_alloc(heap, maj, size);
      if (min) {
        heap_trace(heap, "done: allocated from major");
        return heap_minor_to(min);
      }
      heap_trace(heap, "major doesn't enough contiguous space");
    }

    maj = maj->next;
  }

  heap_trace(heap, "no major with enough space, creating new major");
  maj = heap_major_create(heap, size);
  min = heap_minor_create(maj, size);

  heap_trace(heap, "done: created new major");
  return heap_minor_to(min);
}

void *heap_realloc(struct Heap *heap, void *ptr, size_t size) {
  void *nptr;
  struct HeapMinor *min;

  size = HEAP_ALIGNED(size);

  if (ptr == NULL)
    return heap_alloc(heap, size);

  if (size == 0) {
    heap_free(heap, ptr);
    return NULL;
  }

  min = heap_minor_from(ptr);

  if (!heap_node_check(heap, &min->base))
    return NULL;

  if (min->size >= size) {
    heap_minor_resize(min, size);
    return ptr;
  }

  nptr = heap_alloc(heap, size);
  memcpy(nptr, ptr, min->size);
  heap_free(heap, ptr);
  return nptr;
}

void *heap_calloc(struct Heap *heap, size_t num, size_t size) {
  void *ptr = heap_alloc(heap, num * size);
  memset(ptr, 0, num * size);
  return ptr;
}

void heap_free(struct Heap *heap, void *ptr) {
  struct HeapMinor *min;

  if (!ptr) {
    heap_error(heap, "freeing NULL pointer");
    return;
  }

  min = heap_minor_from(ptr);

  if (!heap_node_check(heap, &min->base))
    return;

  heap_minor_free(heap, min);
}

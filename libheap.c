#include "libheap.h"

// Heap hook functions

void *heap_alloc_block(struct Heap *heap, size_t size) {
  return heap->alloc(heap->ctx, size);
}

void heap_free_block(struct Heap *heap, void *ptr, size_t size) {
  heap->free(heap->ctx, ptr, size);
}

void heap_error(struct Heap *heap, const char *msg) {
  heap->error(heap->ctx, msg);
}

// Heap node functions

bool heap_node_check(struct Heap *heap, struct HeapNode *node) {
  if (node->magic == HEAP_MAGIC)
    return true;

  if (node->magic == HEAP_DEAD) {
    heap_error(heap, "heap double free detected");
    return false;
  }

  size_t overflow = 0;
  for (size_t i = 0; i < sizeof(node->magic); i++) {
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

// Heap major functions

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
      .minor = NULL,
  };

  return maj;
}

struct HeapMinor *heap_major_alloc(struct HeapMajor *maj, size_t size) {
  struct HeapMinor *min = maj->minor;

  while (min) {
    if (min->used == 0 && heap_minor_avail(min) >= size) {
      heap_minor_resize(min, size);
      return min;
    }

    if (min->used && heap_minor_avail(min) >= size + HEAP_ALIGN) {
      return heap_minor_split(min, size);
    }

    min = min->next;
  }

  return NULL;
}

void heap_major_free(struct Heap *heap, struct HeapMajor *maj) {
  heap_node_remove(&maj->base);
  heap_free_block(heap, maj, maj->size);
}

// Heap minor functions

size_t heap_minor_avail(struct HeapMinor *min) { return min->size - min->used; }

struct HeapMinor *heap_minor_create(struct HeapMajor *maj, size_t size) {
  struct HeapMinor *min = (struct HeapMinor *)((uintptr_t)maj + HEAP_ALIGN);

  *min = (struct HeapMinor){
      .magic = HEAP_MAGIC,
      .size = maj->size - HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  maj->used += size + HEAP_ALIGN;
  maj->minor = min;

  return min;
}

struct HeapMinor *heap_minor_split(struct HeapMinor *min, size_t size) {
  struct HeapMajor *maj = min->major;

  struct HeapMinor *newMin = (struct HeapMinor *)((uint8_t *)min + min->used);
  *newMin = (struct HeapMinor){
      .magic = HEAP_MAGIC,
      .size = min->size - min->used - HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  min->size = min->used;
  maj->used += HEAP_ALIGN;
  heap_node_append(&maj->base, &newMin->base);

  return newMin;
}

void heap_minor_free(struct HeapMinor *min) {
  struct HeapMajor *maj = min->major;

  maj->used -= min->size;
  min->used = 0;

  if (min->prev) {
    struct HeapMinor *prev = min->prev;
    prev->size += min->size + HEAP_ALIGN;
    min->magic = HEAP_DEAD;
    maj->used -= HEAP_ALIGN;
    heap_node_remove(&min->base);
    min = prev;
  }

  if (min->next && min->used == 0) {
    struct HeapMinor *next = min->next;
    next->magic = HEAP_DEAD;
    min->size += next->size + HEAP_ALIGN;
    maj->used -= HEAP_ALIGN;
    heap_node_remove(&next->base);
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

// Heap functions

void *heap_alloc(struct Heap *heap, size_t size) {
  size = HEAP_ALIGNED(size);
  if (size == 0) {
    return NULL;
  }

  if (!heap->root) {
    heap->root = heap_major_create(heap, HEAP_MIN_REQU);
    heap->best = heap->root;
    struct HeapMinor *min = heap_minor_create(heap->root, size);
    return heap_minor_to(min);
  }

  if (!heap->best) {
    heap->best = heap->root;
  }

  if (heap_major_avail(heap->best) >= size) {
    struct HeapMinor *min = heap_major_alloc(heap->best, size);
    if (min) {
      return heap_minor_to(min);
    }
  }

  struct HeapMajor *maj = heap->root;

  while (maj) {
    if (heap_major_avail(maj) > heap_major_avail(heap->best)) {
      heap->best = maj;
    }

    if (heap_major_avail(maj) >= size) {
      struct HeapMinor *min = heap_major_alloc(maj, size);
      if (min) {
        return heap_minor_to(min);
      }
    }

    maj = maj->next;
  }

  maj = heap_major_create(heap, size);
  return heap_minor_to(heap_minor_create(maj, size));
}

void *heap_realloc(struct Heap *heap, void *ptr, size_t size) {
  if (ptr == NULL)
    return heap_alloc(heap, size);

  if (size == 0) {
    heap_free(heap, ptr);
    return NULL;
  }

  struct HeapMinor *min = heap_minor_from(ptr);

  if (!heap_node_check(heap, &min->base))
    return NULL;

  if (min->size >= size) {
    heap_minor_resize(min, size);
    return ptr;
  }

  void *nptr = heap_alloc(heap, size);
  memcpy(nptr, ptr, min->size);
  heap_free(heap, ptr);
  return nptr;
}

void *heap_calloc(struct Heap *heap, size_t num, size_t size) {
  return heap_alloc(heap, num * size);
}

void heap_free(struct Heap *heap, void *ptr) {
  if (ptr == NULL) {
    heap_error(heap, "freeing NULL pointer");
    return;
  }

  struct HeapMinor *min = heap_minor_from(ptr);

  if (!heap_node_check(heap, &min->base))
    return;

  heap_minor_free(min);
}

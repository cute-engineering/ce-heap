#include <ce-heap.h>
#include <ce-panic.h>
#include <string.h>

/* Heap hook functions */

void *ce_heap_alloc_block(ce_heap *heap, ce_usize size) {
  return heap->alloc(heap->ctx, size);
}

void ce_heap_free_block(ce_heap *heap, void *ptr, ce_usize size) {
  heap->free(heap->ctx, ptr, size);
}

/* Heap node functions */

bool ce_heap_node_check(ce_heap *heap, ce_heap_node *node) {
  (void)(heap);
  ce_usize overflow = 0, i = 0;

  if (node->magic == CE_HEAP_MAGIC)
    return true;

  if (node->magic == CE_HEAP_DEAD) {
    ce_debug("heap double free detected");
    return false;
  }

  for (i = 0; i < sizeof(node->magic); i++) {
    if (node->m[i] != 0xc0)
      overflow++;
  }

  if (overflow == sizeof(node->magic))
    ce_panic("heap corruption/use-after-free detected");
  else
    ce_panic("heap overflow detected");

  return false;
}

void ce_heap_node_append(ce_heap_node *list, ce_heap_node *node) {
  node->prev = list;
  node->next = list->next;
  if (list->next) {
    list->next->prev = node;
  }
  list->next = node;
}

void ce_heap_node_prepend(ce_heap_node *list, ce_heap_node *node) {
  node->next = list;
  node->prev = list->prev;
  if (list->prev) {
    list->prev->next = node;
  }
  list->prev = node;
}

void ce_heap_node_remove(ce_heap_node *node) {
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

ce_usize ce_heap_major_avail(ce_heap_major *maj) {
  return maj->size - maj->used;
}

ce_heap_major *ce_heap_major_create(ce_heap *heap, ce_usize size) {
  size = size + CE_HEAP_ALIGN;
  size = size < CE_HEAP_MIN_REQU ? CE_HEAP_MIN_REQU : size;
  size = CE_HEAP_PAGE_ALIGNED(size);

  ce_heap_major *maj = (ce_heap_major *)ce_heap_alloc_block(heap, size);
  *maj = (ce_heap_major){
      .magic = CE_HEAP_MAGIC,
      .size = size,
      .used = CE_HEAP_ALIGN,
  };

  return maj;
}

ce_heap_minor *ce_heap_major_alloc(ce_heap *heap, ce_heap_major *maj,
                                   ce_usize size) {
  (void)(heap);
  ce_heap_minor *min = maj->minor;

  while (min) {
    if (!min->used && ce_heap_minor_avail(min) >= size) {
      ce_heap_minor_resize(min, size);
      return min;
    }

    if (min->used && ce_heap_minor_avail(min) >= size + CE_HEAP_ALIGN) {
      return ce_heap_minor_split(min, size);
    }

    min = min->next;
  }

  return NULL;
}

void ce_heap_major_free(ce_heap *heap, ce_heap_major *maj) {
  ce_heap_major *next = maj->next;

  ce_heap_node_remove(&maj->base);
  ce_heap_free_block(heap, maj, maj->size);

  if (heap->root == maj)
    heap->root = next;

  if (heap->best == maj)
    heap->best = NULL;
}

/* Heap minor functions */

ce_usize ce_heap_minor_avail(ce_heap_minor *min) {
  return min->size - min->used;
}

ce_heap_minor *ce_heap_minor_create(ce_heap_major *maj, ce_usize size) {
  ce_heap_minor *min = (ce_heap_minor *)((uintptr_t)maj + CE_HEAP_ALIGN);

  *min = (ce_heap_minor){
      .magic = CE_HEAP_MAGIC,
      .size = ce_heap_major_avail(maj) - CE_HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  maj->used += size + CE_HEAP_ALIGN;
  maj->minor = min;

  return min;
}

ce_heap_minor *ce_heap_minor_split(ce_heap_minor *min, ce_usize size) {
  ce_heap_major *maj = min->major;
  ce_heap_minor *newMin =
      (ce_heap_minor *)((uintptr_t)min + CE_HEAP_ALIGN + min->used);

  *newMin = (ce_heap_minor){
      .magic = CE_HEAP_MAGIC,
      .size = ce_heap_minor_avail(min) - CE_HEAP_ALIGN,
      .used = size,
      .major = maj,
  };

  min->size = min->used;
  maj->used += CE_HEAP_ALIGN + size;
  ce_heap_node_append(&min->base, &newMin->base);

  return newMin;
}

void ce_heap_minor_free(ce_heap *heap, ce_heap_minor *min) {
  ce_heap_major *maj = min->major;
  ce_heap_minor *prev = min->prev;
  ce_heap_minor *next = min->next;

  maj->used -= min->used;
  min->used = 0;

  if (prev) {
    min->magic = CE_HEAP_DEAD;
    prev->size += min->size + CE_HEAP_ALIGN;
    maj->used -= CE_HEAP_ALIGN;

    ce_heap_node_remove(&min->base);
    min = prev;
  }

  if (next && !next->used) {
    next->magic = CE_HEAP_DEAD;
    min->size += next->size + CE_HEAP_ALIGN;
    maj->used -= CE_HEAP_ALIGN;

    ce_heap_node_remove(&next->base);
  }

  if (maj->used == CE_HEAP_ALIGN) {
    ce_heap_major_free(heap, maj);
  }
}

void ce_heap_minor_resize(ce_heap_minor *min, ce_usize size) {
  if (min->used > size) {
    min->major->used -= min->used - size;
  } else {
    min->major->used += size - min->used;
  }
  min->used = size;
}

ce_heap_minor *ce_heap_minor_from(void *ptr) {
  return (ce_heap_minor *)((uintptr_t)ptr - CE_HEAP_ALIGN);
}

void *ce_heap_minor_to(ce_heap_minor *min) {
  return (void *)((uintptr_t)min + CE_HEAP_ALIGN);
}

/* Heap functions */

void *ce_heap_alloc(ce_heap *heap, ce_usize size) {
  ce_heap_major *maj;
  ce_heap_major *prev;
  ce_heap_minor *min;

  size = CE_HEAP_ALIGNED(size);
  if (size == 0) {
    return NULL;
  }

  if (!heap->root) {
    heap->root = ce_heap_major_create(heap, size);
    heap->best = heap->root;
    min = ce_heap_minor_create(heap->root, size);

    return ce_heap_minor_to(min);
  }

  if (!heap->best) {
    heap->best = heap->root;
  }

  if (ce_heap_major_avail(heap->best) >= size) {
    min = ce_heap_major_alloc(heap, heap->best, size);
    if (min) {
      return ce_heap_minor_to(min);
    }
  }

  maj = heap->root;
  while (maj) {
    if (ce_heap_major_avail(maj) > ce_heap_major_avail(heap->best)) {
      heap->best = maj;
    }

    if (ce_heap_major_avail(maj) >= size) {
      min = ce_heap_major_alloc(heap, maj, size);
      if (min) {
        return ce_heap_minor_to(min);
      }
    }

    prev = maj;
    maj = maj->next;
  }

  maj = ce_heap_major_create(heap, size);
  ce_heap_node_append(&prev->base, &maj->base);
  min = ce_heap_minor_create(maj, size);

  return ce_heap_minor_to(min);
}

void *ce_heap_realloc(ce_heap *heap, void *ptr, ce_usize size) {
  void *nptr;
  ce_heap_minor *min;

  size = CE_HEAP_ALIGNED(size);

  if (ptr == NULL)
    return ce_heap_alloc(heap, size);

  if (size == 0) {
    ce_heap_free(heap, ptr);
    return NULL;
  }

  min = ce_heap_minor_from(ptr);

  if (!ce_heap_node_check(heap, &min->base))
    return NULL;

  if (min->size >= size) {
    ce_heap_minor_resize(min, size);
    return ptr;
  }

  nptr = ce_heap_alloc(heap, size);
  memcpy(nptr, ptr, min->size);
  ce_heap_free(heap, ptr);
  return nptr;
}

void *ce_heap_calloc(ce_heap *heap, ce_usize num, ce_usize size) {
  void *ptr = ce_heap_alloc(heap, num * size);
  memset(ptr, 0, num * size);
  return ptr;
}

void ce_heap_free(ce_heap *heap, void *ptr) {
  ce_heap_minor *min;

  if (!ptr) {
    ce_debug("freeing NULL pointer");
    return;
  }

  min = ce_heap_minor_from(ptr);

  if (!ce_heap_node_check(heap, &min->base))
    return;

  ce_heap_minor_free(heap, min);
}

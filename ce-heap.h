#pragma once

#include <ce-base.h>
#include <ce-macros.h>

CE_HEADER_BEGIN

#define CE_HEAP_MAGIC      0xc0c0c0c0c0c0c0c0
#define CE_HEAP_DEAD       0xdeaddeaddeaddead
#define CE_HEAP_ALIGN      (64)
#define CE_HEAP_PAGE_SIZE  (4096)
#define CE_HEAP_MIN_REQU   (4096 * 4)
#define CE_HEAP_ALIGNED(X) (((X) + (CE_HEAP_ALIGN - 1)) & ~(CE_HEAP_ALIGN - 1))
#define CE_HEAP_PAGE_ALIGNED(X) \
    (((X) + (CE_HEAP_PAGE_SIZE - 1)) & ~(CE_HEAP_PAGE_SIZE - 1))

typedef struct ce_heap_node ce_heap_node;
typedef struct ce_heap_major ce_heap_major;
typedef struct ce_heap_minor ce_heap_minor;

struct ce_heap_node
{
    union
    {
        ce_u64 magic;
        ce_u8 m[8];
    };
    ce_heap_node *prev;
    ce_heap_node *next;
};

#define CE_HEAP_NODE(T)    \
    union                  \
    {                      \
        ce_heap_node base; \
        struct             \
        {                  \
            ce_u64 magic;  \
            T *prev;       \
            T *next;       \
        };                 \
    }

struct ce_heap_major
{
    CE_HEAP_NODE(ce_heap_major);

    ce_usize size;
    ce_usize used;
    ce_heap_minor *minor;
};

struct ce_heap_minor
{
    CE_HEAP_NODE(ce_heap_minor);

    ce_usize size;
    ce_usize used;
    ce_heap_major *major;
};

typedef void *ce_heap_alloc_fn(void *ctx, ce_usize size);

typedef void ce_heap_free_fn(void *ctx, void *ptr, ce_usize size);

typedef struct
{
    void *ctx;
    ce_heap_alloc_fn *alloc;
    ce_heap_free_fn *free;
    ce_heap_major *root;
    ce_heap_major *best;
} ce_heap;

/* ---- Internal functions -------------------------------------------------- */

/* Heap hook functions */

void *ce_heap_alloc_block(ce_heap *heap, ce_usize size);

void ce_heap_free_block(ce_heap *heap, void *ptr, ce_usize size);

/* Heap node functions */

bool ce_heap_node_check(ce_heap *heap, ce_heap_node *node);

void ce_heap_node_append(ce_heap_node *node, ce_heap_node *other);

void ce_heap_node_prepend(ce_heap_node *node, ce_heap_node *other);

void ce_heap_node_remove(ce_heap_node *node);

/* Heap major functions */

ce_usize ce_heap_major_avail(ce_heap_major *maj);

ce_heap_major *ce_heap_major_create(ce_heap *heap, ce_usize size);

ce_heap_minor *ce_heap_major_alloc(ce_heap *heap, ce_heap_major *maj,
                                   ce_usize size);

void ce_heap_major_free(ce_heap *heap, ce_heap_major *maj);

/* Heap minor functions */

ce_usize ce_heap_minor_avail(ce_heap_minor *min);

ce_heap_minor *ce_heap_minor_create(ce_heap_major *maj, ce_usize size);

ce_heap_minor *ce_heap_minor_split(ce_heap_minor *min, ce_usize size);

void ce_heap_minor_free(ce_heap *heap, ce_heap_minor *min);

void ce_heap_minor_resize(ce_heap_minor *min, ce_usize size);

ce_heap_minor *ce_heap_minor_from(void *ptr);

void *ce_heap_minor_to(ce_heap_minor *min);

/* ---- Public functions ---------------------------------------------------- */

void *ce_heap_alloc(ce_heap *heap, ce_usize size);

void *ce_heap_realloc(ce_heap *heap, void *ptr, ce_usize size);

void *ce_heap_calloc(ce_heap *heap, ce_usize num, ce_usize size);

void ce_heap_free(ce_heap *heap, void *ptr);

CE_HEADER_END

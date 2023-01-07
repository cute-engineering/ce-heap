#include "impl/impl.h"

int main() {
  struct Heap heap = heap_impl();
  void *p1 = heap_alloc(&heap, 16);
  void *p2 = heap_alloc(&heap, 16);
  return 0;
}
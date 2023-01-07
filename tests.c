#include "impl/impl.h"

int main() {
  struct Heap heap = heap_impl();
  for (int i = 0; i < 100; i++) {
    heap_alloc(&heap, 512);
  }
  return 0;
}
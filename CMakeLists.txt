cmake_minimum_required(VERSION 2.8)

project(LibHeap)
add_library(Heap SHARED libheap.c)
add_library(HeapStatic STATIC libheap.c)
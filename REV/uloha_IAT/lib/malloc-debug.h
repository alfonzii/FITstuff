#ifndef MALLOC_DEBUG
#define MALLOC_DEBUG

#include <stdio.h>

int MallocDebug_init();

int MallocDebug_done();

void *MallocDebug_malloc(size_t size);

void *MallocDebug_calloc(size_t number, size_t size);

void *MallocDebug_realloc(void *memblock, size_t size);

void MallocDebug_free(void *memblock);



#endif
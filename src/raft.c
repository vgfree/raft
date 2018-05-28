#include <stdlib.h>

void *(*__raft_malloc)(size_t) = malloc;
void *(*__raft_calloc)(size_t, size_t) = calloc;
void *(*__raft_realloc)(void *, size_t) = realloc;
void (*__raft_free)(void *) = free;

void raft_set_heap_functions(void *(*_malloc)(size_t),
                             void *(*_calloc)(size_t, size_t),
                             void *(*_realloc)(void *, size_t),
                             void (*_free)(void *))
{
    __raft_malloc = _malloc;
    __raft_calloc = _calloc;
    __raft_realloc = _realloc;
    __raft_free = _free;
}

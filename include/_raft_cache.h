#ifndef _RAFT_CACHE_H_
#define _RAFT_CACHE_H_

#include "raft_types.h"

#define INITIAL_CAPACITY 10

typedef struct
{
    /* size of array */
    raft_index_t    size;

    raft_entry_t    **addr;

    /* the amount of elements in the array */
    raft_index_t    used;

    /* async mark incr entry index */
    raft_index_t    mark;

    /* position of the queue */
    raft_index_t    head, tail;

    /* we compact the log, and thus need to increment the Base Log Index, start from 0 */
    raft_index_t    base;
} raft_cache_private_t;

raft_cache_private_t *raft_cache_make(raft_index_t initial_size);

void raft_cache_free(raft_cache_private_t *me);

void raft_cache_set_base_idx(raft_cache_private_t *me, raft_index_t idx);

/**
 * @return number of entries held within log */
raft_index_t raft_cache_count(raft_cache_private_t *me);

raft_index_t raft_cache_get_entry_head_idx(raft_cache_private_t *me);

/**
 * @return current success store log index */
raft_index_t raft_cache_get_entry_last_idx(raft_cache_private_t *me);

raft_index_t raft_cache_get_entry_mark_idx(raft_cache_private_t *me);

void raft_cache_set_entry_mark_idx(raft_cache_private_t *me, raft_index_t idx);

/*
 * @param[in] idx The entry's index, idx is begin from 1
 * @return entry of index
 */
raft_entry_t *raft_cache_dup_at_idx(raft_cache_private_t *me, raft_index_t idx);

/** Get an array of entries from this index onwards.
 * This is used for batching.
 */
typedef bool (*RAFT_CACHE_FILTER_FCB)(const raft_entry_t *ety, void *usr);
typedef bool (*RAFT_CACHE_FINISH_FCB)(const raft_entry_t *ety, void *usr);
raft_batch_t *raft_cache_dup_among_idx(raft_cache_private_t *me, raft_index_t from_idx, raft_index_t over_idx,
    RAFT_CACHE_FILTER_FCB filter,
    RAFT_CACHE_FINISH_FCB finish,
    void *usr);

/**
 * @return entry term of index, 0 if entry is not exist.
 */
raft_term_t raft_cache_get_term_at_idx(raft_cache_private_t *me, raft_index_t idx);

int raft_cache_pop_tail_entry(raft_cache_private_t *me);

/**
 * Remove oldest entry. */
int raft_cache_pop_head_entry(raft_cache_private_t *me);

int raft_cache_push_alone_entry(raft_cache_private_t *me, raft_entry_t *ety);

int raft_cache_push_batch_entries(raft_cache_private_t *me, raft_batch_t *bat);

#endif /* ifndef _RAFT_CACHE_H_ */


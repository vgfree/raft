/**
 * Copyright (c) 2013, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * @file
 * @brief ADT for managing Raft log entries (aka entries)
 * @author Willem Thiart himself@willemthiart.com
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#include "raft.h"
#include "raft_private.h"

/**
 * Empty the queue. */
static void raft_cache_empty(raft_cache_private_t *me_)
{
    raft_cache_private_t *me = (raft_cache_private_t *)me_;

    me->used = 0;
    me->tail = 0;
    me->head = 0;
    me->base = 0;
    me->mark = 0;
}

raft_cache_private_t *raft_cache_make(raft_index_t initial_size)
{
    raft_cache_private_t *me = (raft_cache_private_t *)__raft_calloc(1, sizeof(raft_cache_private_t));

    if (!me) {
        return NULL;
    }

    me->size = initial_size;
    me->addr = (raft_entry_t **)__raft_calloc(me->size, sizeof(raft_entry_t *));

    if (!me->addr) {
        __raft_free(me);
        return NULL;
    }

    raft_cache_empty(me);
    return me;
}

void raft_cache_free(raft_cache_private_t *me)
{
    __raft_free(me->addr);
    __raft_free(me);
}

void raft_cache_set_base_idx(raft_cache_private_t *me, raft_index_t idx)
{
    assert(idx > 0);

    /* idx starts at 1 */
    idx -= 1;

    me->base = idx;
}

raft_index_t raft_cache_count(raft_cache_private_t *me)
{
    return me->used;
}

static bool raft_index_is_cache_have(raft_cache_private_t *me, raft_index_t idx)
{
    assert(idx >= 0);

    if ((idx == 0) || (idx <= me->base) || (me->base + me->used < idx)) {
        return false;
    } else {
        return true;
    }
}

static raft_index_t raft_index_to_cache_offset(raft_cache_private_t *me, raft_index_t idx)
{
    /* idx starts at 1 */
    idx -= 1;

    return (me->head + idx - me->base) % me->size;
}

raft_entry_t *raft_cache_dup_at_idx(raft_cache_private_t *me, raft_index_t idx)
{
    if (!raft_index_is_cache_have(me, idx)) {
        return NULL;
    }

    raft_index_t    i = raft_index_to_cache_offset(me, idx);
    raft_entry_t    *ety = me->addr[i];
    raft_entry_t    *cpy = raft_entry_make(ety->term, ety->id, ety->type, ety->data.buf, ety->data.len);
    return cpy;
}

raft_index_t raft_cache_get_entry_head_idx(raft_cache_private_t *me)
{
    /* idx starts at 1 */
    return me->base + 1;
}

raft_index_t raft_cache_get_entry_last_idx(raft_cache_private_t *me)
{
    return raft_cache_count(me) + me->base;
}

raft_index_t raft_cache_get_entry_mark_idx(raft_cache_private_t *me)
{
    return me->mark;
}

void raft_cache_set_entry_mark_idx(raft_cache_private_t *me, raft_index_t idx)
{
    raft_index_t cursor = raft_cache_get_entry_last_idx(me);

    assert(idx == me->mark + 1);
    assert(idx > cursor);
    me->mark = idx;
}

static raft_index_t raft_cache_count_from_idx(raft_cache_private_t *me, raft_index_t idx)
{
    /* idx starts at 1 */
    idx -= 1;

    return me->base + me->used - idx;
}

raft_batch_t *raft_cache_dup_among_idx(raft_cache_private_t *me, raft_index_t from_idx, raft_index_t over_idx,
    RAFT_CACHE_FILTER_FCB filter,
    RAFT_CACHE_FINISH_FCB finish,
    void *usr)
{
    assert(over_idx >= from_idx);

    if (!raft_index_is_cache_have(me, from_idx)) {
        return NULL;
    }

    if (!raft_index_is_cache_have(me, over_idx)) {
        return NULL;
    }

    raft_batch_t *bat = NULL;

    int max = over_idx - from_idx + 1;
    assert(raft_cache_count_from_idx(me, from_idx) >= max);

    raft_entry_t    **tmp = __raft_calloc(max, sizeof(raft_entry_t *));
    int             len = 0;

    for (int i = 0; i < max; i++) {
        raft_index_t    j = raft_index_to_cache_offset(me, from_idx + i);
        raft_entry_t    *ety = me->addr[j];

        bool is_filter = (filter) ? filter(ety, usr) : false;

        if (!is_filter) {
            raft_entry_t *cpy = raft_entry_make(ety->term, ety->id, ety->type, ety->data.buf, ety->data.len);
            tmp[len++] = cpy;
        }

        bool is_finish = (finish) ? finish(ety, usr) : false;

        if (is_finish) {
            break;
        }
    }

    if (len) {
        bat = raft_batch_make(len);

        for (int i = 0; i < len; i++) {
            raft_batch_join_entry(bat, i, tmp[i]);
        }
    }

    free(tmp);

    return bat;
}

raft_term_t raft_cache_get_term_at_idx(raft_cache_private_t *me, raft_index_t idx)
{
    if (!raft_index_is_cache_have(me, idx)) {
        return 0;
    }

    raft_index_t    i = raft_index_to_cache_offset(me, idx);
    raft_entry_t    *ety = me->addr[i];
    return ety->term;
}

static int mod(raft_index_t a, raft_index_t b)
{
    int r = a % b;

    return r < 0 ? r + b : r;
}

int raft_cache_pop_tail_entry(raft_cache_private_t *me)
{
    assert(me->used);

    raft_index_t    tail = mod(me->tail - 1, me->size);
    raft_entry_t    *ety = me->addr[tail];
    raft_entry_free(ety);

    me->tail = tail;
    me->used--;
    return 0;
}

int raft_cache_pop_head_entry(raft_cache_private_t *me)
{
    assert(me->used);

    raft_index_t    head = me->head;
    raft_entry_t    *ety = me->addr[head];
    raft_entry_free(ety);

    me->head = mod(me->head + 1, me->size);
    me->used--;
    me->base++;
    return 0;
}

#ifndef min
  #define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
  #define max(a, b) ((a) < (b) ? (b) : (a))
#endif

static int __ensurecapacity(raft_cache_private_t *me, int add)
{
    if (me->used + add <= me->size) {
        return 0;
    }

    int             new_size = max(me->used + add, me->size * 2);
    raft_entry_t    **temp = (raft_entry_t **)__raft_calloc(1, sizeof(raft_entry_t *) * new_size);

    if (!temp) {
        return RAFT_ERR_NOMEM;
    }

    raft_index_t i, j;

    for (i = 0, j = me->head; i < me->used; i++, j++) {
        if (j == me->size) {
            j = 0;
        }

        memcpy(&temp[i], &me->addr[j], sizeof(raft_entry_t *));
    }

    /* clean up old addr */
    __raft_free(me->addr);

    me->size = new_size;
    me->addr = temp;
    me->head = 0;
    me->tail = me->used;
    return 0;
}

int raft_cache_push_alone_entry(raft_cache_private_t *me, raft_entry_t *ety)
{
    int e = __ensurecapacity(me, 1);

    if (e != 0) {
        return e;
    }

    me->addr[me->tail] = ety;

    me->tail = mod(me->tail + 1, me->size);
    me->used++;
    return 0;
}

int raft_cache_push_batch_entries(raft_cache_private_t *me, raft_batch_t *bat)
{
    int e = __ensurecapacity(me, bat->n_entries);

    if (e != 0) {
        return e;
    }

    for (int i = 0; i < bat->n_entries; i++) {
        raft_entry_t *ety = raft_batch_take_entry(bat, i);

        int tail = mod(me->tail + i, me->size);
        me->addr[tail] = ety;
    }

    me->tail = mod(me->tail + bat->n_entries, me->size);
    me->used += bat->n_entries;
    return 0;
}


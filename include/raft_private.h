/**
 * Copyright (c) 2013, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * @file
 * @author Willem Thiart himself@willemthiart.com
 */

#ifndef RAFT_PRIVATE_H_
#define RAFT_PRIVATE_H_

#include "raft_types.h"

#include "_raft_cache.h"
#include "_raft_node.h"
#include "_raft_server.h"

/* Heap functions */
extern void *(*__raft_malloc)(size_t size);
extern void *(*__raft_calloc)(size_t nmemb, size_t size);
extern void *(*__raft_realloc)(void *ptr, size_t size);
extern void (*__raft_free)(void *ptr);

int raft_votes_is_majority(const int nnodes, const int nvotes);

// #include "1.h"

/**
 * Add entries to the server's log.
 * This should be used to reload persistent state, ie. the commit log.
 * Don't add entries if we've already added these entries (based off ID)
 * Don't add entries with ID=0
 * @param[in] bat The entraies to be appended
 * @return
 *  0 on success;
 *  RAFT_ERR_SHUTDOWN server should shutdown
 *  RAFT_ERR_NOMEM memory allocation failure */
extern int log_append_batch(raft_server_private_t *me_, raft_batch_t *bat);

int raft_append_entry(raft_server_t *me, raft_entry_t *ety);

int log_load_from_snapshot(raft_server_private_t *me, raft_index_t idx, raft_term_t term);

raft_index_t raft_get_num_snapshottable_logs(raft_server_t *me_);

/** Confirm if a msg_entry_response has been committed.
 * @param[in] r The response we want to check */
int raft_msg_entry_response_committed(raft_server_t *me_,
    const msg_entry_response_t                      *r);

#endif /* RAFT_PRIVATE_H_ */


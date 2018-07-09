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

#include "_raft_logger.h"
#include "_raft_cache.h"
#include "_raft_node.h"
#include "_raft_server.h"

/* Heap functions */
extern void *(*__raft_malloc)(size_t size);
extern void *(*__raft_calloc)(size_t nmemb, size_t size);
extern void *(*__raft_realloc)(void *ptr, size_t size);
extern void (*__raft_free)(void *ptr);

int raft_votes_is_majority(const int nnodes, const int nvotes);

#endif /* RAFT_PRIVATE_H_ */


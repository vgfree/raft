/**
 * Copyright (c) 2013, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * @file
 * @author Willem Thiart himself@willemthiart.com
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* for varags */
#include <stdarg.h>

#include "raft.h"
#include "raft_private.h"

static void raft_randomize_election_timeout(raft_server_private_t *me)
{
    /* [election_timeout, 2 * election_timeout) */
    me->election_timeout_rand = me->election_timeout + rand() % me->election_timeout;
    raft_printf(LOG_INFO, "randomize election timeout to %d", me->election_timeout_rand);
}

void raft_server_set_election_timeout(raft_server_private_t *me, int millisec)
{
    me->election_timeout = millisec;
    raft_randomize_election_timeout(me);
}

void raft_server_set_request_timeout(raft_server_private_t *me, int millisec)
{
    me->request_timeout = millisec;
}

raft_node_id_t raft_server_get_my_nodeid(raft_server_private_t *me)
{
    if (!me->node) {
        return -1;
    }

    return raft_node_get_id(me->node);
}

int raft_server_get_election_timeout(raft_server_private_t *me)
{
    return me->election_timeout;
}

int raft_server_get_request_timeout(raft_server_private_t *me)
{
    return me->request_timeout;
}

int raft_server_get_num_nodes(raft_server_private_t *me)
{
    return me->num_nodes;
}

int raft_server_get_num_voting_nodes(raft_server_private_t *me)
{
    int i, num = 0;

    for (i = 0; i < me->num_nodes; i++) {
        if (raft_node_is_active((raft_node_private_t *)me->nodes[i]) && raft_node_is_voting((raft_node_private_t *)me->nodes[i])) {
            num++;
        }
    }

    return num;
}

int raft_server_get_timeout_elapsed(raft_server_private_t *me)
{
    return me->timeout_elapsed;
}

raft_node_id_t raft_server_get_voted_for(raft_server_private_t *me)
{
    return me->voted_for;
}

int raft_server_set_voted_for(raft_server_private_t *me, const raft_node_id_t id)
{
    assert(me->cb.persist_vote);
    int e = me->cb.persist_vote((raft_server_t *)me, me->udata, id);

    if (0 == e) {
        me->voted_for = id;
    }

    return e;
}

int raft_server_set_current_term(raft_server_private_t *me, const raft_term_t term)
{
    if (me->current_term < term) {
        raft_node_id_t voted_for = -1;// TODO: remove voted_for

        assert(me->cb.persist_term);
        int e = me->cb.persist_term((raft_server_t *)me, me->udata, term, voted_for);

        if (0 == e) {
            me->current_term = term;
            me->voted_for = voted_for;
        }

        return e;
    }

    return 0;
}

raft_term_t raft_server_get_current_term(raft_server_private_t *me)
{
    return me->current_term;
}

void raft_server_set_commit_idx(raft_server_private_t *me, raft_index_t idx)
{
    assert(me->commit_idx <= idx);
    assert(idx <= raft_cache_get_entry_last_idx(me->log));
    me->commit_idx = idx;
}

void raft_server_set_last_applied_idx(raft_server_private_t *me, raft_index_t idx)
{
    me->last_applied_idx = idx;
}

raft_index_t raft_server_get_last_applied_idx(raft_server_private_t *me)
{
    return me->last_applied_idx;
}

void raft_server_set_last_applying_idx(raft_server_private_t *me, raft_index_t idx)
{
    me->last_applying_idx = idx;
}

raft_index_t raft_server_get_last_applying_idx(raft_server_private_t *me)
{
    return me->last_applying_idx;
}

raft_index_t raft_server_get_commit_idx(raft_server_private_t *me)
{
    return me->commit_idx;
}

void raft_server_set_state(raft_server_private_t *me, int state)
{
    /* if became the leader, then update the current leader entry */
    if (state == RAFT_STATE_LEADER) {
        me->current_leader = me->node;
    } else {
        me->current_leader = NULL;
    }

    me->state = state;
    me->timeout_elapsed = 0;
    raft_randomize_election_timeout(me);
}

int raft_server_get_state(raft_server_private_t *me)
{
    return me->state;
}

raft_node_t *raft_server_get_node(raft_server_private_t *me, raft_node_id_t nodeid)
{
    int i;

    for (i = 0; i < me->num_nodes; i++) {
        if (nodeid == raft_node_get_id(me->nodes[i])) {
            return me->nodes[i];
        }
    }

    return NULL;
}

raft_node_t *raft_server_get_my_node(raft_server_private_t *me)
{
    int i;

    for (i = 0; i < me->num_nodes; i++) {
        if (raft_server_get_my_nodeid(me) == raft_node_get_id(me->nodes[i])) {
            return me->nodes[i];
        }
    }

    return NULL;
}

raft_node_t *raft_server_get_node_by_idx(raft_server_private_t *me, const int idx)
{
    return me->nodes[idx];
}

raft_node_id_t raft_server_get_current_leader(raft_server_private_t *me)
{
    if (me->current_leader) {
        return raft_node_get_id(me->current_leader);
    }

    return -1;
}

raft_node_t *raft_server_get_current_leader_node(raft_server_private_t *me)
{
    return me->current_leader;
}

void *raft_server_get_udata(raft_server_private_t *me)
{
    return me->udata;
}

int raft_server_is_follower(raft_server_private_t *me)
{
    return raft_server_get_state(me) == RAFT_STATE_FOLLOWER;
}

int raft_server_is_leader(raft_server_private_t *me)
{
    return raft_server_get_state(me) == RAFT_STATE_LEADER;
}

int raft_server_is_candidate(raft_server_private_t *me)
{
    return raft_server_get_state(me) == RAFT_STATE_CANDIDATE;
}

int raft_is_connected(raft_server_t *me_)
{
    return ((raft_server_private_t *)me_)->connected;
}

int raft_snapshot_is_in_progress(raft_server_t *me_)
{
    return ((raft_server_private_t *)me_)->snapshot_in_progress;
}

raft_index_t raft_get_snapshot_last_idx(raft_server_t *me_)
{
    return ((raft_server_private_t *)me_)->snapshot_last_idx;
}

raft_term_t raft_get_snapshot_last_term(raft_server_t *me_)
{
    return ((raft_server_private_t *)me_)->snapshot_last_term;
}

void raft_set_snapshot_metadata(raft_server_t *me_, raft_term_t term, raft_index_t idx)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    me->snapshot_last_term = term;
    me->snapshot_last_idx = idx;
}


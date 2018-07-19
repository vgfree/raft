/**
 * Copyright (c) 2013, Willem-Hendrik Thiart
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * @file
 * @brief Implementation of a Raft server
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

#ifndef min
  #define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
  #define max(a, b) ((a) < (b) ? (b) : (a))
#endif

raft_server_private_t *raft_server_new(void)
{
    raft_server_private_t *me =
        (raft_server_private_t *)__raft_calloc(1, sizeof(raft_server_private_t));

    if (!me) {
        return NULL;
    }

    me->current_term = 0;
    me->voted_for = -1;
    me->timeout_elapsed = 0;
    me->request_timeout = 200;
    me->election_timeout = 1000;
    me->log = raft_cache_make(INITIAL_CAPACITY);

    if (!me->log) {
        __raft_free(me);
        return NULL;
    }

    // me->voting_cfg_change_log_idx = -1;
    raft_server_set_state(me, RAFT_STATE_FOLLOWER);

    me->snapshot_in_progress = 0;
    raft_set_snapshot_metadata((raft_server_t *)me, 0, 0);

    return me;
}

void raft_server_free(raft_server_private_t *me)
{
    for (int i = 0; i < me->num_nodes; i++) {
        raft_node_free((raft_node_private_t *)me->nodes[i]);
    }

    if (me->nodes) {
        __raft_free(me->nodes);
    }

    raft_cache_free(me->log);

    __raft_free(me);
}

void raft_server_set_callbacks(raft_server_private_t *me, raft_cbs_t *funcs, void *udata)
{
    memcpy(&me->cb, funcs, sizeof(raft_cbs_t));
    me->udata = udata;
}

int raft_server_del_entries_after_from_idx(raft_server_private_t *me, raft_index_t idx)
{
    assert(raft_server_get_commit_idx(me) < idx);

    if (idx <= me->voting_cfg_change_log_idx) {
        me->voting_cfg_change_log_idx = -1;
    }

    if (0 == idx) {
        return -1;
    }

#if 0
    if (idx < me->log->base) {
        idx = me->log->base;
    }
#else
    assert(idx >= raft_cache_get_entry_head_idx(me->log));
#endif

    raft_index_t    last = raft_cache_get_entry_last_idx(me->log);
    raft_index_t    todo = (last >= idx) ? (last - idx + 1) : 0;

    for (raft_index_t i = 0; i < todo; i++) {
        raft_index_t    idx_del = raft_cache_get_entry_last_idx(me->log);
        raft_entry_t    *ety = raft_cache_dup_at_idx(me->log, idx_del);
        assert(ety);

        if (me->cb.log_pop) {
            int e = me->cb.log_pop((raft_server_t *)me, raft_server_get_udata(me), ety, idx_del);

            if (0 != e) {
                raft_entry_free(ety);
                return e;
            }
        }

        raft_server_revert_cfg_entry(me, ety, idx_del);
        raft_entry_free(ety);

        raft_cache_pop_tail_entry(me->log);
    }

    return 0;
}

int raft_server_del_entries_ahead_from_idx(raft_server_private_t *me, raft_index_t idx)
{
    raft_index_t i = raft_cache_get_entry_head_idx(me->log);

    for (; i <= idx; i++) {
        raft_index_t    idx_del = raft_cache_get_entry_head_idx(me->log);
        raft_entry_t    *ety = raft_cache_dup_at_idx(me->log, idx_del);
        assert(ety);

        if (me->cb.log_poll) {
            int e = me->cb.log_poll((raft_server_t *)me, raft_server_get_udata(me), ety, idx_del);

            if (0 != e) {
                raft_entry_free(ety);
                return e;
            }
        }

        raft_entry_free(ety);
        raft_cache_pop_head_entry(me->log);
    }

    return 0;
}

int raft_server_election_start(raft_server_private_t *me)
{
    raft_printf(LOG_INFO, "election starting: %d %d, term: %d ci: %d",
        me->election_timeout_rand,
        me->timeout_elapsed,
        me->current_term,
        raft_cache_get_entry_last_idx(me->log));

    return raft_server_become_candidate(me);
}

void raft_server_become_leader(raft_server_private_t *me)
{
    int i;

    raft_printf(LOG_INFO, "becoming leader term:%d", raft_server_get_current_term(me));

    raft_server_set_state(me, RAFT_STATE_LEADER);

    for (i = 0; i < me->num_nodes; i++) {
        raft_node_t *node = me->nodes[i];

        if ((me->node == node) || !raft_node_is_active((raft_node_private_t *)node)) {
            continue;
        }

        raft_node_set_next_idx((raft_node_private_t *)node, raft_cache_get_entry_last_idx(me->log) + 1);
        raft_node_set_match_idx((raft_node_private_t *)node, 0);
        raft_server_send_appendentries(me, node);
    }
}

int raft_server_become_candidate(raft_server_private_t *me)
{
    int i;

    raft_printf(LOG_INFO, "becoming candidate");

    int e = raft_server_set_current_term(me, raft_server_get_current_term(me) + 1);

    if (0 != e) {
        return e;
    }

    for (i = 0; i < me->num_nodes; i++) {
        raft_node_fix_vote_for_me((raft_node_private_t *)me->nodes[i], 0);
    }

    raft_server_set_voted_for(me, me->node ? raft_node_get_id(me->node) : -1);
    raft_server_set_state(me, RAFT_STATE_CANDIDATE);

    for (i = 0; i < me->num_nodes; i++) {
        raft_node_t *node = me->nodes[i];

        if ((me->node != node) &&
            raft_node_is_active((raft_node_private_t *)node) &&
            raft_node_is_voting((raft_node_private_t *)node)) {
            raft_server_send_requestvote(me, node);
        }
    }

    return 0;
}

void raft_server_become_follower(raft_server_private_t *me)
{
    raft_printf(LOG_INFO, "becoming follower");
    raft_server_set_state(me, RAFT_STATE_FOLLOWER);
}

static int raft_server_send_appendentries_to_all(raft_server_private_t *me)
{
    me->timeout_elapsed = 0;

    for (int i = 0; i < me->num_nodes; i++) {
        if ((me->node == me->nodes[i]) || !raft_node_is_active((raft_node_private_t *)me->nodes[i])) {
            continue;
        }

        int e = raft_server_send_appendentries(me, me->nodes[i]);

        if (0 != e) {
            return e;
        }
    }

    return 0;
}

int raft_server_periodic(raft_server_private_t *me, int msec_since_last_period)
{
    me->timeout_elapsed += msec_since_last_period;

    raft_node_t *node = raft_server_get_my_node(me);

    /* Only one voting node means it's safe for us to become the leader */
    if ((!raft_server_is_leader(me)) &&
        (1 == raft_server_get_num_voting_nodes(me)) &&
        raft_node_is_voting((raft_node_private_t *)node)) {
        raft_server_become_leader(me);
    }

    if (raft_server_is_leader(me)) {
        if (me->request_timeout <= me->timeout_elapsed) {/*timeout to resend*/
            raft_server_send_appendentries_to_all(me);
        }
    } else if ((me->election_timeout_rand <= me->timeout_elapsed) &&
        !raft_snapshot_is_in_progress((raft_server_t *)me)) {
        /* Don't become the leader when building snapshots or bad things will
         * happen when we get a client request */
        if ((1 < raft_server_get_num_voting_nodes(me)) &&
            raft_node_is_voting((raft_node_private_t *)node)) {
            int e = raft_server_election_start(me);

            if (0 != e) {
                return e;
            }
        }
    }

    if ((raft_server_get_last_applied_idx(me) < raft_server_get_commit_idx(me)) &&
        !raft_snapshot_is_in_progress((raft_server_t *)me)) {
        int e = raft_server_async_apply_entries_start(me);

        if (0 != e) {
            return e;
        }
    }

    return 0;
}

int raft_server_voting_change_is_in_progress(raft_server_private_t *me)
{
    return me->voting_cfg_change_log_idx != -1;
}

int raft_server_recv_appendentries_response(raft_server_private_t   *me,
    raft_node_t                                                     *node,
    msg_appendentries_response_t                                    *r)
{
    raft_printf(LOG_INFO,
        "received appendentries response %s ci:%d rci:%d 1stidx:%d",
        r->success == 1 ? "SUCCESS" : "fail",
        raft_cache_get_entry_last_idx(me->log),
        r->current_idx,
        r->first_idx);

    if (!node) {
        return -1;
    }

    if (!raft_server_is_leader(me)) {
        return RAFT_ERR_NOT_LEADER;
    }

    /* If response contains term T > currentTerm: set currentTerm = T
     *   and convert to follower (§5.3) */
    if (me->current_term < r->term) {
        int e = raft_server_set_current_term(me, r->term);

        if (0 != e) {
            return e;
        }

        raft_server_become_follower(me);
        return 0;
    } else if (me->current_term != r->term) {
        return 0;
    }

    raft_index_t match_idx = raft_node_get_match_idx((raft_node_private_t *)node);

    if (0 == r->success) {
        /* If AppendEntries fails because of log inconsistency:
         *   decrement nextIndex and retry (§5.3) */
        raft_index_t next_idx = raft_node_get_next_idx(node);
        assert(0 < next_idx);
        /* Stale response -- ignore */
        assert(match_idx <= next_idx - 1);

        if (match_idx == next_idx - 1) {
            return 0;
        }

        if (r->current_idx < next_idx - 1) {
            raft_node_set_next_idx((raft_node_private_t *)node, min(r->current_idx + 1, raft_cache_get_entry_last_idx(me->log)));
        } else {
            raft_node_set_next_idx((raft_node_private_t *)node, next_idx - 1);
        }

        /* retry */
        raft_server_send_appendentries(me, node);
        return 0;
    }

    if (!raft_node_is_voting((raft_node_private_t *)node) &&
        !raft_server_voting_change_is_in_progress(me) &&
        (raft_cache_get_entry_last_idx(me->log) <= r->current_idx + 1) &&/*FIXME: <= r->current_idx ???*/
        !raft_node_is_voting_committed(node) &&
        me->cb.node_has_sufficient_logs &&
        (0 == raft_node_has_sufficient_logs((raft_node_private_t *)node))
        ) {
        int e = me->cb.node_has_sufficient_logs((raft_server_t *)me, me->udata, node);

        if (0 == e) {
            raft_node_set_has_sufficient_logs((raft_node_private_t *)node, 1);
        }
    }

    if (r->current_idx <= match_idx) {
        return 0;
    }

    assert(r->current_idx <= raft_cache_get_entry_last_idx(me->log));

    raft_node_set_next_idx((raft_node_private_t *)node, r->current_idx + 1);
    raft_node_set_match_idx((raft_node_private_t *)node, r->current_idx);

    /* Update commit idx */
    raft_index_t point = r->current_idx;

    if (point) {
        raft_term_t term = raft_cache_get_term_at_idx(me->log, point);

        if ((raft_server_get_commit_idx(me) < point) && (term == me->current_term)) {
            int i, votes = 1;

            for (i = 0; i < me->num_nodes; i++) {
                raft_node_t *node = me->nodes[i];

                if ((me->node != node) &&
                    raft_node_is_active((raft_node_private_t *)node) &&
                    raft_node_is_voting((raft_node_private_t *)node) &&
                    (point <= raft_node_get_match_idx((raft_node_private_t *)node))) {
                    votes++;
                }
            }

            if (raft_server_get_num_voting_nodes(me) / 2 < votes) {
                raft_server_set_commit_idx(me, point);
            }
        }
    }

    /* Aggressively send remaining entries */
    if (raft_cache_get_entry_last_idx(me->log) >= raft_node_get_next_idx(node)) {
        raft_server_send_appendentries(me, node);
    }

    /* periodic applies committed entries lazily */

    return 0;
}

int raft_server_recv_appendentries(
    raft_server_private_t   *me,
    raft_node_t             *node,
    msg_appendentries_t     *ae)
{
    int e = 0;
    int append_evts = me->append_evts;

    me->append_evts++;
    int             success = 0;
    raft_index_t    current_idx = raft_cache_get_entry_last_idx(me->log);
    bool            can_update_commit = false;

    if (ae->bat) {
        /* not heartbeat */
        raft_printf(LOG_INFO, "recvd appendentries t:%d ci:%d lc:%d pli:%d plt:%d #%d",
            ae->term,
            raft_cache_get_entry_last_idx(me->log),
            ae->leader_commit,
            ae->prev_log_idx,
            ae->prev_log_term,
            ae->bat->n_entries);
    }

    if (me->current_term < ae->term) {
        raft_printf(LOG_INFO, "update term %d", ae->term);
        e = raft_server_set_current_term(me, ae->term);

        if (0 != e) {
            goto out;
        }

        raft_server_become_follower(me);
    } else if (me->current_term > ae->term) {
        /* 1. Reply false if term < currentTerm (§5.1) */
        raft_printf(LOG_INFO, "AE term %d is less than current term %d",
            ae->term, me->current_term);
        goto out;
    } else {
        /*term is same.*/
        assert(me->current_term == ae->term);

        if (raft_server_is_candidate(me)) {
            raft_server_become_follower(me);
        } else {
            if (raft_server_is_leader(me)) {
                raft_printf(LOG_ERR, "I'm the leader.");
            }

            me->timeout_elapsed = 0;
        }
    }

    /* update current leader because ae->term is up to date */
    me->current_leader = node;

    /* Not the first appendentries we've received */
    /* NOTE: the log starts at 1 */
    if (0 < ae->prev_log_idx) {
        raft_term_t term = raft_cache_get_term_at_idx(me->log, ae->prev_log_idx);

        /* 2. Reply false if log doesn't contain an entry at prevLogIndex
         *   whose term matches prevLogTerm (§5.3) */
        if (ae->prev_log_idx == me->snapshot_last_idx) {
            /* Is a snapshot */
            if (me->snapshot_last_term != ae->prev_log_term) {
                /* Should never happen; something is seriously wrong! */
                raft_printf(LOG_INFO, "Snapshot AE prev conflicts with committed entry");
                e = RAFT_ERR_SHUTDOWN;
                goto out;
            }
        } else if (!term) {
            raft_printf(LOG_INFO, "AE no log at prev_idx %d", ae->prev_log_idx);
            goto out;
        } else if (term != ae->prev_log_term) {
            raft_printf(LOG_INFO, "AE term doesn't match prev_term (ie. %d vs %d) ci:%d comi:%d lcomi:%d pli:%d",
                term, ae->prev_log_term, raft_cache_get_entry_last_idx(me->log),
                raft_server_get_commit_idx(me), ae->leader_commit, ae->prev_log_idx);

            if (ae->prev_log_idx <= raft_server_get_commit_idx(me)) {
                /* Should never happen; something is seriously wrong! */
                raft_printf(LOG_INFO, "AE prev conflicts with committed entry");
                e = RAFT_ERR_SHUTDOWN;
                goto out;
            }

            /* Delete all the following log entries because they don't match */
            e = raft_server_del_entries_after_from_idx(me, ae->prev_log_idx);
            goto out;
        }
    }

    success = 1;
    current_idx = ae->prev_log_idx;

    /* 3. If an existing entry conflicts with a new one (same index
     *   but different terms), delete the existing entry and all that
     *   follow it (§5.3) */
    int i;

    for (i = 0; ae->bat && i < ae->bat->n_entries; i++) {
        raft_entry_t    *ety = ae->bat->entries[i];
        raft_index_t    ety_index = ae->prev_log_idx + 1 + i;

        raft_term_t term = raft_cache_get_term_at_idx(me->log, ety_index);

        if (!term) {
            /* not exist */
            break;
        } else if (term != ety->term) {
            if (ety_index <= raft_server_get_commit_idx(me)) {
                /* Should never happen; something is seriously wrong! */
                raft_printf(LOG_INFO, "AE entry conflicts with committed entry ci:%d comi:%d lcomi:%d pli:%d",
                    raft_cache_get_entry_last_idx(me->log), raft_server_get_commit_idx(me),
                    ae->leader_commit, ae->prev_log_idx);
                e = RAFT_ERR_SHUTDOWN;
                goto out;
            }

            e = raft_server_del_entries_after_from_idx(me, ety_index);

            if (0 != e) {
                goto out;
            }

            break;
        }

        current_idx = ety_index;
    }

    can_update_commit = true;

    if (append_evts) {
        goto out;
    }

    if (ae->bat) {
        /* Pick up remainder in case of mismatch or missing entry */
        int num = ae->bat->n_entries - i;

        if (num) {
            raft_index_t    come_idx = current_idx + 1;
            raft_index_t    over_idx = current_idx + num;
            raft_printf(LOG_INFO, "---------new entrys from %d to %d\n", come_idx, over_idx);

            raft_batch_t *bat = raft_batch_make(num);

            for (int j = 0; j < ae->bat->n_entries; j++) {
                raft_entry_t *ety = raft_batch_take_entry(ae->bat, j);

                if (j < i) {
                    raft_entry_free(ety);
                } else {
                    raft_batch_join_entry(bat, j - i, ety);
                }
            }

            raft_batch_free(ae->bat);
            ae->bat = NULL;

            return raft_server_async_append_entries_start(me, node, bat, come_idx, ae->leader_commit, ae->prev_log_idx + 1);
        }
    }

out:

    if (ae->bat) {
        for (int i = 0; i < ae->bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_take_entry(ae->bat, i);
            raft_entry_free(ety);
        }

        raft_batch_free(ae->bat);
        ae->bat = NULL;
    }

    return raft_server_async_append_entries_finish(me, node, can_update_commit, ae->leader_commit, success, current_idx, ae->prev_log_idx + 1);
}

static int raft_server_already_voted(raft_server_private_t *me)
{
    return raft_server_get_voted_for(me) != -1;
}

static int __should_grant_vote(raft_server_private_t *me, msg_requestvote_t *vr)
{
    if (!raft_node_is_voting((raft_node_private_t *)raft_get_my_node((void *)me))) {
        return 0;
    }

    if (vr->term < raft_server_get_current_term(me)) {
        return 0;
    }

    /* TODO: if voted for is candidate return 1 (if below checks pass) */
    if (raft_server_already_voted(me)) {
        return 0;
    }

    /* Below we check if log is more up-to-date... */

    raft_index_t current_idx = raft_cache_get_entry_last_idx(me->log);

    /* Our log is definitely not more up-to-date if it's empty! */
    if (0 == current_idx) {
        return 1;
    }

    raft_term_t ety_term = raft_cache_get_term_at_idx(me->log, current_idx);

    // TODO: add test
    if (!ety_term) {
        ety_term = (me->snapshot_last_idx == current_idx) ? me->snapshot_last_term : 0;
    }

    if (!ety_term) {
        return 0;
    }

    if (ety_term < vr->last_log_term) {
        return 1;
    }

    if ((vr->last_log_term == ety_term) && (current_idx <= vr->last_log_idx)) {
        return 1;
    }

    return 0;
}

int raft_server_send_requestvote_response(raft_server_private_t *me, raft_node_t *node, msg_requestvote_response_t *r)
{
    assert(node);
    assert(node != me->node);

    raft_printf(LOG_INFO, "sending requestvote response to node [%d]", raft_node_get_id(node));

    int e = 0;

    if (me->cb.send_requestvote_response) {
        e = me->cb.send_requestvote_response((raft_server_t *)me, me->udata, node, r);
    }

    return e;
}

int raft_server_recv_requestvote(raft_server_private_t *me, raft_node_t *node, msg_requestvote_t *vr)
{
    int e = 0;
    int vote_granted = 0;

    if (!node) {
        node = raft_server_get_node(me, vr->candidate_id);
    }

    /* Reject request if we have a leader */
    if (me->current_leader && (me->current_leader != node) &&
        (me->timeout_elapsed < me->election_timeout)) {
        vote_granted = 0;
        goto done;
    }

    if (raft_server_get_current_term(me) < vr->term) {
        e = raft_server_set_current_term(me, vr->term);

        if (0 != e) {
            vote_granted = 0;
            goto done;
        }

        raft_server_become_follower(me);
    }

    if (__should_grant_vote(me, vr)) {
        /* It shouldn't be possible for a leader or candidate to grant a vote
         * Both states would have voted for themselves */
        assert(!(raft_server_is_leader(me) || raft_server_is_candidate(me)));

        e = raft_server_set_voted_for(me, vr->candidate_id);

        if (0 == e) {
            vote_granted = 1;
        } else {
            vote_granted = 0;
        }

        /* must be in an election. */
        me->current_leader = NULL;

        me->timeout_elapsed = 0;
    } else {
        /* It's possible the candidate node has been removed from the cluster but
         * hasn't received the appendentries that confirms the removal. Therefore
         * the node is partitioned and still thinks its part of the cluster. It
         * will eventually send a requestvote. This is error response tells the
         * node that it might be removed. */
        if (!node) {
            vote_granted = RAFT_REQUESTVOTE_ERR_UNKNOWN_NODE;
            goto done;
        } else {
            vote_granted = 0;
        }
    }

done:
    raft_printf(LOG_INFO, "node requested vote: %d replying: %s",
        node,
        vote_granted == 1 ? "granted" :
        vote_granted == 0 ? "not granted" : "unknown");

    msg_requestvote_response_t r = { 0 };
    r.vote_granted = vote_granted;
    r.term = raft_server_get_current_term(me);

    raft_server_send_requestvote_response(me, node, &r);

    return e;
}

int raft_votes_is_majority(const int num_nodes, const int nvotes)
{
    if (num_nodes < nvotes) {
        return 0;
    }

    int half = num_nodes / 2;
    return half + 1 <= nvotes;
}

int raft_server_recv_requestvote_response(raft_server_private_t *me, raft_node_t *node, msg_requestvote_response_t *r)
{
    raft_printf(LOG_INFO, "node responded to requestvote status: %s",
        r->vote_granted == 1 ? "granted" :
        r->vote_granted == 0 ? "not granted" : "unknown");

    if (!raft_server_is_candidate(me)) {
        return 0;
    } else if (raft_server_get_current_term(me) < r->term) {
        int e = raft_server_set_current_term(me, r->term);

        if (0 != e) {
            return e;
        }

        raft_server_become_follower(me);
        return 0;
    } else if (raft_server_get_current_term(me) != r->term) {
        /* The node who voted for us would have obtained our term.
         * Therefore this is an old message we should ignore.
         * This happens if the network is pretty choppy. */
        return 0;
    }

    raft_printf(LOG_INFO, "node responded to requestvote status:%s ct:%d rt:%d",
        r->vote_granted == 1 ? "granted" :
        r->vote_granted == 0 ? "not granted" : "unknown",
        me->current_term,
        r->term);

    switch (r->vote_granted)
    {
        case RAFT_REQUESTVOTE_ERR_GRANTED:

            if (node) {
                raft_node_fix_vote_for_me((raft_node_private_t *)node, 1);
            }

            int votes = raft_server_get_nvotes_for_me(me);

            if (raft_votes_is_majority(raft_server_get_num_voting_nodes(me), votes)) {
                raft_server_become_leader(me);
            }

            break;

        case RAFT_REQUESTVOTE_ERR_NOT_GRANTED:
            break;

        case RAFT_REQUESTVOTE_ERR_UNKNOWN_NODE:

            if (raft_node_is_voting((raft_node_private_t *)raft_server_get_my_node(me)) &&
                (me->connected == RAFT_NODE_STATUS_DISCONNECTING)) {
                return RAFT_ERR_SHUTDOWN;
            }

            break;

        default:
            assert(0);
    }

    return 0;
}

int raft_server_async_retain_entries_start(raft_server_private_t *me, raft_batch_t *bat, raft_index_t idx, void *usr)
{
    int n_entries = bat->n_entries;

    if (n_entries == 1) {
        raft_entry_t *ety = raft_batch_view_entry(bat, 0);

        if (raft_entry_is_voting_cfg_change(ety)) {
            me->voting_cfg_change_log_idx = raft_cache_get_entry_last_idx(me->log);
        }
    } else {
        for (int i = 0; i < n_entries; i++) {
            raft_entry_t *ety = raft_batch_view_entry(bat, i);
            assert(!raft_entry_is_voting_cfg_change(ety));
        }
    }

    void *ud = raft_server_get_udata(me);

    raft_index_t start_idx = raft_cache_get_entry_last_idx(me->log) + 1;
    assert(start_idx == idx);

    /*
     * if success, you need call like this:
     * raft_server_dispose_entries_cache(me, true, bat, idx);
     * raft_server_async_retain_entries_finish(me, 0, n_entries, usr);
     */
    assert(me->cb.log_retain);
    return me->cb.log_retain((raft_server_t *)me, ud, bat, start_idx, usr);
}

int raft_server_async_retain_entries_finish(raft_server_private_t *me, int result, int n_entries, void *usr)
{
    /*非leader不该变更*/
    assert(raft_server_is_leader(me));
    me->retain_evts--;

    if (result == 0) {
        for (int i = 0; i < me->num_nodes; i++) {
            raft_node_t *node = me->nodes[i];

            if ((me->node == node) ||
                !node ||
                !raft_node_is_active((raft_node_private_t *)node) ||
                !raft_node_is_voting((raft_node_private_t *)node)) {
                continue;
            }

            /* Only send new entries.
             * Don't send the entry to peers who are behind, to prevent them from
             * becoming congested. */
            raft_index_t next_idx = raft_node_get_next_idx(node);

            if (next_idx == raft_cache_get_entry_last_idx(me->log)) {
                raft_server_send_appendentries(me, node);
            }
        }

        /* if we're the only node, we can consider the entry committed */
        if (1 == raft_server_get_num_voting_nodes(me)) {
            raft_server_set_commit_idx(me, raft_cache_get_entry_last_idx(me->log));
        }

        /* FIXME: is this required if raft_server_async_retain_entries_start does this too? */
        if (n_entries == 1) {
            raft_entry_t *ety = raft_cache_dup_at_idx(me->log, raft_cache_get_entry_last_idx(me->log));

            if (raft_entry_is_voting_cfg_change(ety)) {
                me->voting_cfg_change_log_idx = raft_cache_get_entry_last_idx(me->log);
            }

            raft_entry_free(ety);
        }
    }

    assert(me->cb.log_retain_done);
    return me->cb.log_retain_done((raft_server_t *)me, me->udata, result, me->current_term,
               raft_cache_get_entry_last_idx(me->log) - n_entries + 1, raft_cache_get_entry_last_idx(me->log), usr);// FIXME:
}

int raft_server_retain_entries(raft_server_private_t *me, msg_batch_t *bat, void *usr)
{
    int result = 0;
    int retain_evts = me->retain_evts;

    me->retain_evts++;

    if (bat->n_entries == 1) {
        raft_entry_t *ety = raft_batch_view_entry(bat, 0);

        if (raft_entry_is_voting_cfg_change(ety)) {
            /* Only one voting cfg change at a time */
            if (raft_server_voting_change_is_in_progress(me)) {
                result = RAFT_ERR_ONE_VOTING_CHANGE_ONLY;
                goto out;
            }

            /* Multi-threading: need to fail here because user might be
             * snapshotting membership settings. */
            if (raft_snapshot_is_in_progress((raft_server_t *)me)) {
                result = RAFT_ERR_SNAPSHOT_IN_PROGRESS;
                goto out;
            }
        }
    } else {
        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_view_entry(bat, i);
            assert(!raft_entry_is_voting_cfg_change(ety));
        }
    }

    if (!raft_server_is_leader(me)) {
        result = RAFT_ERR_NOT_LEADER;
        goto out;
    }

    if (retain_evts) {
        result = RAFT_ERR_NEEDS_WAIT;
        goto out;
    }

    for (int i = 0; i < bat->n_entries; i++) {
        raft_entry_t *ety = raft_batch_view_entry(bat, i);
        ety->term = me->current_term;

        raft_printf(LOG_INFO, "received entry t:%d id: %d idx: %d",
            me->current_term, ety->id, raft_cache_get_entry_last_idx(me->log) + 1);
    }

    return raft_server_async_retain_entries_start(me, bat, raft_cache_get_entry_last_idx(me->log) + 1, usr);

out:
    return raft_server_async_retain_entries_finish(me, result, 0, usr);
}

int raft_server_remind_entries(raft_server_private_t *me, void *usr)
{
    int     result = 0;
    void    *ud = raft_server_get_udata(me);

    /* Multi-threading: need to fail here because user might be
     * snapshotting membership settings. */
    if (raft_snapshot_is_in_progress((raft_server_t *)me)) {
        result = RAFT_ERR_SNAPSHOT_IN_PROGRESS;
        goto out;
    }

    if (!raft_server_is_leader(me)) {
        result = RAFT_ERR_NOT_LEADER;
        goto out;
    }

    raft_index_t    applied_idx = raft_server_get_last_applied_idx(me);
    raft_index_t    commit_idx = raft_server_get_commit_idx(me);
    assert(applied_idx <= commit_idx);

    raft_index_t    from_idx = applied_idx + 1;
    raft_index_t    over_idx = commit_idx;

    raft_batch_t *bat = raft_cache_dup_among_idx(me->log, from_idx, over_idx,
            NULL,
            NULL,
            NULL);

    assert(me->cb.log_remind);
    return me->cb.log_remind((raft_server_t *)me, ud, bat, from_idx, usr);

out:
    assert(me->cb.log_remind_done);
    return me->cb.log_remind_done((raft_server_t *)me, ud, result, usr);
}

int raft_server_send_requestvote(raft_server_private_t *me, raft_node_t *node)
{
    assert(node);
    assert(node != me->node);

    raft_printf(LOG_INFO, "sending requestvote to node [%d]", raft_node_get_id(node));

    msg_requestvote_t rv;
    rv.term = me->current_term;
    rv.last_log_idx = raft_cache_get_entry_last_idx(me->log);
    rv.last_log_term = raft_cache_get_term_at_idx(me->log, rv.last_log_idx);
    rv.candidate_id = raft_server_get_my_nodeid(me);

    int e = 0;

    if (me->cb.send_requestvote) {
        e = me->cb.send_requestvote((raft_server_t *)me, me->udata, node, &rv);
    }

    return e;
}

static bool _finish_by_different_entry_type(const raft_entry_t *ety, void *usr)
{
    raft_entry_t *cmp = (raft_entry_t *)usr;

    if (ety->type == cmp->type) {
        return false;
    } else {
        return true;
    }
}

raft_batch_t *raft_server_get_series_same_type_entries_from_idx(raft_server_private_t *me, raft_index_t idx)
{
    raft_entry_t *ety = raft_cache_dup_at_idx(me->log, idx);

    if (!ety) {
        return NULL;
    } else {
        raft_batch_t *bat = raft_cache_dup_among_idx(me->log, idx, raft_cache_get_entry_last_idx(me->log),
                NULL,
                _finish_by_different_entry_type,
                (void *)ety);
        raft_entry_free(ety);
        assert((!bat) || (bat->entries && 0 < bat->n_entries));
        return bat;
    }
}

int raft_server_send_appendentries(raft_server_private_t *me, raft_node_t *node)
{
    assert(node);
    assert(node != me->node);

    raft_index_t next_idx = raft_node_get_next_idx(node);

    /* figure out if the client needs a snapshot sent */
    if ((0 < me->snapshot_last_idx) && (next_idx < me->snapshot_last_idx)) {
        if (me->cb.send_snapshot) {
            me->cb.send_snapshot((raft_server_t *)me, me->udata, node);
        }

        return RAFT_ERR_NEEDS_SNAPSHOT;
    }

    msg_appendentries_t ae = {};
    ae.term = me->current_term;
    ae.leader_commit = raft_server_get_commit_idx(me);
    ae.bat = raft_server_get_series_same_type_entries_from_idx(me, next_idx);
    ae.n_entries = ae.bat ? ae.bat->n_entries : 0;

    /* previous log is the log just before the new logs */
    ae.prev_log_idx = 0;
    ae.prev_log_term = 0;

    if (1 < next_idx) {
        raft_term_t prev_term = raft_cache_get_term_at_idx(me->log, next_idx - 1);

        if (!prev_term) {
            ae.prev_log_idx = me->snapshot_last_idx;
            ae.prev_log_term = me->snapshot_last_term;
        } else {
            ae.prev_log_idx = next_idx - 1;
            ae.prev_log_term = prev_term;
        }
    }

    raft_printf(LOG_INFO, "sending appendentries node: ci:%d comi:%d t:%d lc:%d pli:%d plt:%d",
        raft_cache_get_entry_last_idx(me->log),
        raft_server_get_commit_idx(me),
        ae.term,
        ae.leader_commit,
        ae.prev_log_idx,
        ae.prev_log_term);

    assert(me->cb.send_appendentries);
    return me->cb.send_appendentries((raft_server_t *)me, me->udata, node, &ae);
}

static int _compare_node(const void *x, const void *y)
{
    raft_node_private_t *a = (raft_node_private_t *)x;
    raft_node_private_t *b = (raft_node_private_t *)y;

    return a->id < b->id ? -1 : a->id > b->id ? 1 : 0;
}

raft_node_t *raft_server_add_node(raft_server_private_t *me, void *udata, raft_node_id_t id, int is_self)
{
    /* set to voting if node already exists */
    raft_node_t *node = raft_server_get_node(me, id);

    if (node) {
        if (!raft_node_is_voting((raft_node_private_t *)node)) {
            raft_node_set_voting(node, 1);
            return node;
        } else {
            /* we shouldn't add a node twice */
            return NULL;
        }
    }

    node = (raft_node_t *)raft_node_new(udata, id);

    if (!node) {
        return NULL;
    }

    void *p = __raft_realloc(me->nodes, sizeof(void *) * (me->num_nodes + 1));

    if (!p) {
        raft_node_free((raft_node_private_t *)node);
        return NULL;
    }

    me->num_nodes++;
    me->nodes = p;
    me->nodes[me->num_nodes - 1] = node;

    if (is_self) {
        me->node = (raft_node_t *)node;
    }

    /* sort by id */
    qsort(me->nodes, me->num_nodes, sizeof(raft_node_t *), _compare_node);

    if (me->cb.notify_membership_event) {
        me->cb.notify_membership_event((raft_server_t *)me, raft_server_get_udata(me), node, RAFT_MEMBERSHIP_ADD);
    }

    return node;
}

raft_node_t *raft_server_add_non_voting_node(raft_server_private_t *me, void *udata, raft_node_id_t id, int is_self)
{
    if (raft_server_get_node(me, id)) {
        return NULL;
    }

    raft_node_t *node = raft_server_add_node(me, udata, id, is_self);

    if (!node) {
        return NULL;
    }

    raft_node_set_voting(node, 0);
    return node;
}

void raft_server_remove_node(raft_server_private_t *me, raft_node_id_t id)
{
    assert(id >= 0);
    raft_node_private_t *node = NULL;

    int i, found = 0;

    for (i = 0; i < me->num_nodes; i++) {
        node = (raft_node_private_t *)me->nodes[i];

        if (node->id == id) {
            found = 1;
            break;
        }
    }

    assert(found);
    assert(node);

    if (me->cb.notify_membership_event) {
        me->cb.notify_membership_event((raft_server_t *)me, raft_server_get_udata(me), (raft_node_t *)node, RAFT_MEMBERSHIP_REMOVE);
    }

    memmove(&me->nodes[i], &me->nodes[i + 1], sizeof(*me->nodes) * (me->num_nodes - i - 1));
    me->num_nodes--;

    raft_node_free(node);
}

int raft_server_get_nvotes_for_me(raft_server_private_t *me)
{
    int i, votes;

    for (i = 0, votes = 0; i < me->num_nodes; i++) {
        if ((me->node != me->nodes[i]) &&
            raft_node_is_active((raft_node_private_t *)me->nodes[i]) &&
            raft_node_is_voting((raft_node_private_t *)me->nodes[i]) &&
            raft_node_has_vote_for_me((raft_node_private_t *)me->nodes[i])) {
            votes += 1;
        }
    }

    if (raft_server_get_voted_for(me) == raft_server_get_my_nodeid(me)) {
        votes += 1;
    }

    return votes;
}

#if 0

/** Confirm if a msg_entry_response has been committed.
 * @param[in] r The response we want to check */
int raft_msg_entry_response_committed(raft_server_t *me_,
    const msg_entry_response_t                      *r)
{
    raft_server_private_t   *me = (raft_server_private_t *)me_;
    raft_entry_t            *ety = raft_cache_dup_at_idx(me->log, r->idx);

    if (!ety) {
        return 0;
    }

    /* entry from another leader has invalidated this entry message */
    if (r->term != ety->term) {
        return -1;
    }

    return r->idx <= raft_server_get_commit_idx(me);
}

#endif /* if 0 */

int raft_server_async_apply_entries_start(raft_server_private_t *me)
{
    if (raft_snapshot_is_in_progress((raft_server_t *)me)) {
        return 0;
    }

    /* Don't apply after the commit_idx */
    if (raft_server_get_last_applying_idx(me) == raft_server_get_commit_idx(me)) {
        return 0;
    }

    assert(raft_server_get_last_applying_idx(me) < raft_server_get_commit_idx(me));

    raft_index_t    from_idx = raft_server_get_last_applying_idx(me) + 1;
    raft_index_t    over_idx = raft_server_get_commit_idx(me);

    raft_batch_t *bat = raft_cache_dup_among_idx(me->log, from_idx, over_idx,
            NULL,
            NULL,
            NULL);

    if (!bat) {
        return -1;
    }

    raft_printf(LOG_INFO, "applying log: from %d over %d", from_idx, over_idx);

    raft_server_set_last_applying_idx(me, over_idx);

    if (me->cb.log_apply) {
        int e = me->cb.log_apply((raft_server_t *)me, me->udata, bat, from_idx);

        if (RAFT_ERR_SHUTDOWN == e) {
            raft_server_async_apply_entries_finish(me, false, bat, from_idx);
            return RAFT_ERR_SHUTDOWN;
        }
    }

    return 0;
}

int raft_server_async_apply_entries_finish(raft_server_private_t *me, bool ok, raft_batch_t *bat, raft_index_t idx)
{
    raft_index_t    from_idx = idx;
    raft_index_t    over_idx = idx + bat->n_entries - 1;

    if (from_idx > raft_server_get_last_applied_idx(me) + 1) {
        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_take_entry(bat, i);
            raft_entry_free(ety);
        }

        raft_batch_free(bat);
        return 0;
    }

    assert(from_idx == raft_server_get_last_applied_idx(me) + 1);

    if (ok) {
        raft_server_set_last_applied_idx(me, over_idx);

        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_take_entry(bat, i);

            /* voting cfg change is now complete */
            if (from_idx + i == me->voting_cfg_change_log_idx) {
                me->voting_cfg_change_log_idx = -1;
            }

            raft_server_apply_cfg_entry(me, ety, from_idx + i);

            raft_entry_free(ety);
        }

        raft_batch_free(bat);
    } else {
        raft_server_set_last_applying_idx(me, raft_server_get_last_applied_idx(me));

        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_take_entry(bat, i);
            raft_entry_free(ety);
        }

        raft_batch_free(bat);
    }

    return 0;
}

void raft_server_effect_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx)
{
    if (!raft_entry_is_cfg_change(ety)) {
        return;
    }

    raft_node_id_t  node_id = me->cb.log_get_node_id((raft_server_t *)me, raft_server_get_udata(me), ety, idx);
    raft_node_id_t  self_id = raft_server_get_my_nodeid(me);
    int             is_self = (node_id == self_id) ? 1 : 0;

    raft_node_t *node = raft_server_get_node(me, node_id);

    switch (ety->type)
    {
        case RAFT_LOGTYPE_ADD_NONVOTING_NODE:

            if (!is_self) {
                if (node && !raft_node_is_active((raft_node_private_t *)node)) {
                    raft_node_set_active(node, 1);
                } else if (!node) {
                    node = raft_server_add_non_voting_node(me, NULL, node_id, is_self);
                    assert(node);
                }
            }

            break;

        case RAFT_LOGTYPE_ADD_NODE:
            node = raft_server_add_node(me, NULL, node_id, is_self);
            assert(node);
            assert(raft_node_is_voting((raft_node_private_t *)node));
            break;

        case RAFT_LOGTYPE_DEMOTE_NODE:

            if (node) {
                raft_node_set_voting(node, 0);
            }

            break;

        case RAFT_LOGTYPE_REMOVE_NODE:

            if (node) {
                raft_node_set_active(node, 0);
            }

            break;

        default:
            assert(0);
    }
}

void raft_server_revert_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx)
{
    if (!raft_entry_is_cfg_change(ety)) {
        return;
    }

    raft_node_id_t  node_id = me->cb.log_get_node_id((raft_server_t *)me, raft_server_get_udata(me), ety, idx);
    raft_node_id_t  self_id = raft_server_get_my_nodeid(me);
    int             is_self = (node_id == self_id) ? 1 : 0;

    raft_node_t *node = raft_server_get_node(me, node_id);

    switch (ety->type)
    {
        case RAFT_LOGTYPE_DEMOTE_NODE:

            if (node) {
                raft_node_set_voting(node, 1);
            }

            break;

        case RAFT_LOGTYPE_REMOVE_NODE:

            if (node) {
                raft_node_set_active(node, 1);
            }

            break;

        case RAFT_LOGTYPE_ADD_NONVOTING_NODE:
            assert(node);
            raft_server_remove_node(me, node_id);
            assert(!is_self);
            break;

        case RAFT_LOGTYPE_ADD_NODE:

            if (node) {
                raft_node_set_voting(node, 0);
            }

            break;

        default:
            assert(0);
            break;
    }
}

void raft_server_apply_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx)
{
    if (!raft_entry_is_cfg_change(ety)) {
        return;
    }

    raft_node_id_t  node_id = me->cb.log_get_node_id((raft_server_t *)me, raft_server_get_udata(me), ety, idx);
    raft_node_id_t  self_id = raft_server_get_my_nodeid(me);
    int             is_self = (node_id == self_id) ? 1 : 0;

    raft_node_t *node = raft_server_get_node(me, node_id);

    switch (ety->type)
    {
        case RAFT_LOGTYPE_ADD_NODE:
            raft_node_set_addition_committed((raft_node_private_t *)node, 1);
            raft_node_set_voting_committed((raft_node_private_t *)node, 1);
            /* Membership Change: confirm connection with cluster */
            raft_node_set_has_sufficient_logs((raft_node_private_t *)node, 1);

            if (is_self) {
                me->connected = RAFT_NODE_STATUS_CONNECTED;
            }

            break;

        case RAFT_LOGTYPE_ADD_NONVOTING_NODE:
            raft_node_set_addition_committed((raft_node_private_t *)node, 1);
            break;

        case RAFT_LOGTYPE_DEMOTE_NODE:

            if (node) {
                raft_node_set_voting_committed((raft_node_private_t *)node, 0);
            }

            break;

        case RAFT_LOGTYPE_REMOVE_NODE:

            if (node) {
                raft_server_remove_node(me, node_id);
            }

            break;

        default:
            break;
    }
}

raft_index_t raft_get_num_snapshottable_logs(raft_server_t *me_)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    if (raft_cache_count(me->log) <= 1) {// ? <
        return 0;
    }

    return raft_server_get_commit_idx(me) - raft_cache_get_entry_head_idx(me->log);// TODO
}

int raft_begin_snapshot(raft_server_t *me_)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    if (raft_get_num_snapshottable_logs(me_) == 0) {
        return -1;
    }

    raft_index_t snapshot_target = raft_server_get_commit_idx(me);

    if (snapshot_target == 0) {
        return -1;
    }

    raft_entry_t *ety = raft_cache_dup_at_idx(me->log, snapshot_target);

    if (!ety) {
        return -1;
    }

    /* we need to get all the way to the commit idx */
    int e = raft_server_async_apply_entries_start(me);// FIXME: this is become async.

    if (e != 0) {
        return e;
    }

    assert(raft_server_get_commit_idx(me) == raft_server_get_last_applied_idx(me));

    raft_set_snapshot_metadata(me_, ety->term, snapshot_target);
    me->snapshot_in_progress = 1;

    raft_printf(LOG_INFO,
        "begin snapshot sli:%d slt:%d slogs:%d\n",
        me->snapshot_last_idx,
        me->snapshot_last_term,
        raft_get_num_snapshottable_logs(me_));

    return 0;
}

int raft_end_snapshot(raft_server_t *me_)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    if (!me->snapshot_in_progress || (me->snapshot_last_idx == 0)) {
        return -1;
    }

    assert(raft_get_num_snapshottable_logs(me_) != 0);
    assert(me->snapshot_last_idx == raft_server_get_commit_idx(me));

    /* If needed, remove compacted logs */
    raft_index_t    end = raft_server_get_commit_idx(me);
    int             e = raft_server_del_entries_ahead_from_idx(me, end);

    if (e != 0) {
        return -1;
    }

    me->snapshot_in_progress = 0;

    raft_printf(LOG_INFO,
        "end snapshot base:%d commit-index:%d current-index:%d\n",
        raft_cache_get_entry_head_idx(me->log),
        raft_server_get_commit_idx(me),
        raft_cache_get_entry_last_idx(me->log));

    if (!raft_server_is_leader(me)) {
        return 0;
    }

    raft_index_t i = 0;

    for (i = 0; i < me->num_nodes; i++) {
        raft_node_t *node = me->nodes[i];

        if ((me->node == node) || !raft_node_is_active((raft_node_private_t *)node)) {
            continue;
        }

        raft_index_t next_idx = raft_node_get_next_idx(node);

        /* figure out if the client needs a snapshot sent */
        if ((0 < me->snapshot_last_idx) && (next_idx < me->snapshot_last_idx)) {
            if (me->cb.send_snapshot) {
                me->cb.send_snapshot(me_, me->udata, node);
            }
        }
    }

    assert(raft_cache_count(me->log) == 1);

    return 0;
}

int raft_begin_load_snapshot(
    raft_server_t   *me_,
    raft_term_t     last_included_term,
    raft_index_t    last_included_index)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    if (last_included_index == -1) {
        return -1;
    }

    if ((last_included_index == 0) || (last_included_term == 0)) {
        return -1;
    }

    /* loading the snapshot will break cluster safety */
    if (last_included_index < me->last_applied_idx) {
        return -1;
    }

    /* snapshot was unnecessary */
    if (last_included_index < raft_cache_get_entry_last_idx(me->log)) {
        return -1;
    }

    if ((last_included_term == me->snapshot_last_term) && (last_included_index == me->snapshot_last_idx)) {
        return RAFT_ERR_SNAPSHOT_ALREADY_LOADED;
    }

    me->current_term = last_included_term;
    me->voted_for = -1;
    raft_server_set_state(me, RAFT_STATE_FOLLOWER);

    log_load_from_snapshot((raft_server_t *)me, last_included_index, last_included_term);

    if (raft_server_get_commit_idx(me) < last_included_index) {
        raft_server_set_commit_idx(me, last_included_index);
    }

    me->last_applied_idx = last_included_index;
    raft_set_snapshot_metadata(me_, last_included_term, me->last_applied_idx);

    /* remove all nodes but self */
    int i, my_node_by_idx = 0;

    for (i = 0; i < me->num_nodes; i++) {
        if (raft_server_get_my_nodeid(me) == raft_node_get_id(me->nodes[i])) {
            my_node_by_idx = i;
        } else {
            raft_node_set_active(me->nodes[i], 0);
        }
    }

    /* this will be realloc'd by a raft_server_add_node */
    me->nodes[0] = me->nodes[my_node_by_idx];
    me->num_nodes = 1;

    raft_printf(LOG_INFO,
        "loaded snapshot sli:%d slt:%d slogs:%d\n",
        me->snapshot_last_idx,
        me->snapshot_last_term,
        raft_get_num_snapshottable_logs(me_));

    return 0;
}

int raft_end_load_snapshot(raft_server_t *me_)
{
    raft_server_private_t   *me = (raft_server_private_t *)me_;
    int                     i;

    /* Set nodes' voting status as committed */
    for (i = 0; i < me->num_nodes; i++) {
        raft_node_t *node = me->nodes[i];
        raft_node_set_voting_committed((raft_node_private_t *)node, raft_node_is_voting((raft_node_private_t *)node));
        raft_node_set_addition_committed((raft_node_private_t *)node, 1);

        if (raft_node_is_voting((raft_node_private_t *)node)) {
            raft_node_set_has_sufficient_logs((raft_node_private_t *)node, 1);
        }
    }

    return 0;
}

int log_load_from_snapshot(raft_server_t *me, raft_index_t idx, raft_term_t term)
{
    // raft_cache_empty(me->log);//TODO: add
    ((raft_server_private_t *)me)->log->base = idx;

    return 0;
}

raft_index_t raft_server_dispose_entries_cache(raft_server_private_t *me, bool ok, raft_batch_t *bat, raft_index_t idx)
{
    if (ok) {
        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_view_entry(bat, i);
            raft_server_effect_cfg_entry(me, ety, idx + i);
        }

        int e = raft_cache_push_batch_entries(me->log, bat);
        assert(0 == e);

        raft_batch_free(bat);
    } else {
        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_take_entry(bat, i);
            raft_entry_free(ety);
        }

        raft_batch_free(bat);
    }

    return raft_cache_get_entry_last_idx(me->log);
}

int raft_server_async_append_entries_start(raft_server_private_t *me, raft_node_t *node, raft_batch_t *bat, raft_index_t idx,
    raft_index_t leader_commit, raft_index_t rsp_first_idx)
{
    if (bat->n_entries == 1) {
        raft_entry_t *ety = raft_batch_view_entry(bat, 0);

        if (raft_entry_is_voting_cfg_change(ety)) {
            me->voting_cfg_change_log_idx = raft_cache_get_entry_last_idx(me->log);
        }
    } else {
        for (int i = 0; i < bat->n_entries; i++) {
            raft_entry_t *ety = raft_batch_view_entry(bat, i);
            assert(!raft_entry_is_voting_cfg_change(ety));
        }
    }

    void *ud = raft_server_get_udata(me);

    raft_index_t start_idx = raft_cache_get_entry_last_idx(me->log) + 1;
    assert(start_idx == idx);

    /*
     * if success, you need call like this:
     * raft_server_dispose_entries_cache(me, true, bat, idx);
     * raft_server_async_append_entries_finish(me, node, true, leader_commit, 1, raft_cache_get_entry_last_idx(me->log), rsp_first_idx);
     */
    assert(me->cb.log_append);
    return me->cb.log_append((raft_server_t *)me, ud, bat, start_idx, node, leader_commit, rsp_first_idx);
}

int raft_server_async_append_entries_finish(raft_server_private_t *me, raft_node_t *node, bool can_update_commit, raft_index_t leader_commit,
    int rsp_success, raft_index_t rsp_current_idx, raft_index_t rsp_first_idx)
{
    if (rsp_success) {
        /*leader不该变更*/
        assert(!raft_server_is_leader(me));
    }

    me->append_evts--;

    if (can_update_commit) {
        /* 4. If leaderCommit > commitIndex, set commitIndex =
         *   min(leaderCommit, index of most recent entry) */
        if (raft_server_get_commit_idx(me) < leader_commit) {
            raft_index_t last_log_idx = max(raft_cache_get_entry_last_idx(me->log), 1);
            raft_server_set_commit_idx(me, min(last_log_idx, leader_commit));
        }
    }

    msg_appendentries_response_t r = { 0 };

    r.success = rsp_success;
    r.current_idx = rsp_current_idx;
    r.term = me->current_term;
    r.first_idx = rsp_first_idx;

    return raft_server_send_appendentries_response(me, node, &r);
}

int raft_server_send_appendentries_response(raft_server_private_t *me, raft_node_t *node, msg_appendentries_response_t *r)
{
    assert(node);
    assert(node != me->node);

    raft_printf(LOG_INFO, "sending appendentries response to node [%d]", raft_node_get_id(node));

    assert(me->cb.send_appendentries_response);
    return me->cb.send_appendentries_response((raft_server_t *)me, me->udata, node, r);
}

#include "raft_server_properties.c"


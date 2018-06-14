#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "raft.h"
#include "raft_private.h"

void *(*__raft_malloc)(size_t) = malloc;
void    *(*__raft_calloc)(size_t, size_t) = calloc;
void    *(*__raft_realloc)(void *, size_t) = realloc;
void    (*__raft_free)(void *) = free;

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

raft_entry_t *raft_entry_make(unsigned int term, unsigned int id, int type,
    void *buf, unsigned int len)
{
    raft_entry_t *ety = __raft_calloc(1, sizeof(raft_entry_t));

    assert(ety);

    ety->term = term;
    ety->id = id;
    ety->type = type;

    if (buf && (len > 0)) {
        void *data = __raft_malloc(len);
        assert(data);
        memcpy(data, buf, len);
        ety->data.buf = data;
        ety->data.len = len;
    }

    return ety;
}

void raft_entry_free(raft_entry_t *ety)
{
    if (!ety) {
        return;
    }

    if (ety->data.buf) {
        free(ety->data.buf);
    }

    free(ety);
}

raft_batch_t *raft_batch_make(int n_entries)
{
    raft_batch_t *bat = __raft_calloc(1, sizeof(raft_batch_t) + (n_entries * sizeof(raft_entry_t *)));

    bat->n_entries = n_entries;
    return bat;
}

void raft_batch_free(raft_batch_t *bat)
{
    for (int i = 0; i < bat->n_entries; i++) {
        assert(bat->entries[i] == NULL);
    }

    __raft_free(bat);
}

int raft_batch_join_entry(raft_batch_t *bat, int i, raft_entry_t *ety)
{
    assert(i < bat->n_entries);
    assert(bat->entries[i] == NULL);

    bat->entries[i] = ety;
    return 0;
}

raft_entry_t *raft_batch_view_entry(raft_batch_t *bat, int i)
{
    assert(i < bat->n_entries);

    raft_entry_t *ety = bat->entries[i];
    assert(ety != NULL);
    return ety;
}

raft_entry_t *raft_batch_take_entry(raft_batch_t *bat, int i)
{
    assert(i < bat->n_entries);

    raft_entry_t *ety = bat->entries[i];
    assert(ety != NULL);
    bat->entries[i] = NULL;
    return ety;
}

raft_server_t *raft_new(void)
{
    return (raft_server_t *)raft_server_new();
}

void raft_free(raft_server_t *me)
{
    raft_server_free((raft_server_private_t *)me);
}

void raft_set_callbacks(raft_server_t *me, raft_cbs_t *funcs, void *udata)
{
    raft_server_set_callbacks((raft_server_private_t *)me, funcs, udata);
}

raft_node_t *raft_add_node(raft_server_t *me, void *user_data, raft_node_id_t id, int is_self)
{
    return (raft_node_t *)raft_server_add_node((raft_server_private_t *)me, user_data, id, is_self);
}

raft_node_t *raft_add_non_voting_node(raft_server_t *me, void *udata, raft_node_id_t id, int is_self)
{
    return (raft_node_t *)raft_server_add_non_voting_node((raft_server_private_t *)me, udata, id, is_self);
}

void raft_remove_node(raft_server_t *me, raft_node_id_t id)
{
    raft_server_remove_node((raft_server_private_t *)me, id);
}

raft_node_t *raft_get_node(raft_server_t *me, const raft_node_id_t id)
{
    return (raft_node_t *)raft_server_get_node((raft_server_private_t *)me, id);
}

raft_node_id_t raft_get_my_nodeid(raft_server_t *me)
{
    return raft_server_get_my_nodeid((raft_server_private_t *)me);
}

raft_node_t *raft_get_my_node(raft_server_t *me)
{
    return (raft_node_t *)raft_server_get_my_node((raft_server_private_t *)me);
}

int raft_get_num_nodes(raft_server_t *me)
{
    return raft_server_get_num_nodes((raft_server_private_t *)me);
}

int raft_get_num_voting_nodes(raft_server_t *me)
{
    return raft_server_get_num_voting_nodes((raft_server_private_t *)me);
}

raft_node_t *raft_get_node_by_idx(raft_server_t *me, const int idx)
{
    return raft_server_get_node_by_idx((raft_server_private_t *)me, idx);
}

raft_node_id_t raft_get_current_leader(raft_server_t *me)
{
    return raft_server_get_current_leader((raft_server_private_t *)me);
}

raft_node_t *raft_get_current_leader_node(raft_server_t *me)
{
    return raft_server_get_current_leader_node((raft_server_private_t *)me);
}

void *raft_get_udata(raft_server_t *me)
{
    return raft_server_get_udata((raft_server_private_t *)me);
}

void raft_set_election_timeout(raft_server_t *me, int msec)
{
    raft_server_set_election_timeout((raft_server_private_t *)me, msec);
}

int raft_get_election_timeout(raft_server_t *me)
{
    return raft_server_get_election_timeout((raft_server_private_t *)me);
}

void raft_set_request_timeout(raft_server_t *me, int msec)
{
    raft_server_set_request_timeout((raft_server_private_t *)me, msec);
}

int raft_get_request_timeout(raft_server_t *me)
{
    return raft_server_get_request_timeout((raft_server_private_t *)me);
}

int raft_get_timeout_elapsed(raft_server_t *me)
{
    return raft_server_get_timeout_elapsed((raft_server_private_t *)me);
}

int raft_get_state(raft_server_t *me)
{
    return raft_server_get_state((raft_server_private_t *)me);
}

int raft_is_follower(raft_server_t *me)
{
    return raft_server_is_follower((raft_server_private_t *)me);
}

int raft_is_leader(raft_server_t *me)
{
    return raft_server_is_leader((raft_server_private_t *)me);
}

int raft_is_candidate(raft_server_t *me)
{
    return raft_server_is_candidate((raft_server_private_t *)me);
}

int raft_set_current_term(raft_server_t *me, const raft_term_t term)
{
    return raft_server_set_current_term((raft_server_private_t *)me, term);
}

raft_term_t raft_get_current_term(raft_server_t *me)
{
    return raft_server_get_current_term((raft_server_private_t *)me);
}

int raft_set_voted_for(raft_server_t *me, const raft_node_id_t id)
{
    return raft_server_set_voted_for((raft_server_private_t *)me, id);
}

raft_index_t raft_get_commit_idx(raft_server_t *me)
{
    return raft_server_get_commit_idx((raft_server_private_t *)me);
}

void raft_set_commit_idx(raft_server_t *me, raft_index_t commit_idx)
{
    raft_server_set_commit_idx((raft_server_private_t *)me, commit_idx);
}

void raft_set_reload_begin_idx(raft_server_t *me, raft_index_t begin_idx)
{
    raft_cache_set_base_idx(((raft_server_private_t *)me)->log, begin_idx ? begin_idx : 1);
}

int raft_reload_entry(raft_server_t *me_, raft_entry_t *ety)
{
    raft_server_private_t *me = (raft_server_private_t *)me_;

    if (raft_entry_is_voting_cfg_change(ety)) {
        me->voting_cfg_change_log_idx = raft_cache_get_entry_last_idx(((raft_server_private_t *)me)->log);
    }

    raft_index_t idx = raft_cache_get_entry_last_idx(me->log) + 1;
    // FIXME:not do log_offer is ok?
    raft_server_effect_cfg_entry(me, ety, idx);

    return raft_cache_push_alone_entry(me->log, ety);
}

int raft_periodic(raft_server_t *me, int msec_elapsed)
{
    return raft_server_periodic((raft_server_private_t *)me, msec_elapsed);
}

int raft_recv_appendentries(raft_server_t   *me,
    raft_node_t                             *node,
    msg_appendentries_t                     *ae)
{
    return raft_server_recv_appendentries((raft_server_private_t *)me, node, ae);
}

int raft_recv_appendentries_response(raft_server_t  *me,
    raft_node_t                                     *node,
    msg_appendentries_response_t                    *r)
{
    return raft_server_recv_appendentries_response((raft_server_private_t *)me, node, r);
}

int raft_recv_requestvote(raft_server_t *me, raft_node_t *node, msg_requestvote_t *vr)
{
    return raft_server_recv_requestvote((raft_server_private_t *)me, node, vr);
}

int raft_recv_requestvote_response(raft_server_t *me, raft_node_t *node, msg_requestvote_response_t *r)
{
    return raft_server_recv_requestvote_response((raft_server_private_t *)me, node, r);
}

int raft_retain_entries(raft_server_t *me, msg_batch_t *bat, void *usr)
{
    return raft_server_retain_entries((raft_server_private_t *)me, bat, usr);
}

int raft_async_apply_entries_finish(raft_server_t *me, bool ok, raft_batch_t *bat, raft_index_t idx)
{
	return raft_server_async_apply_entries_finish((raft_server_private_t *)me, ok, bat, idx);
}

int raft_async_append_entries_finish(raft_server_t *me, raft_node_t *node, bool can_update_commit, raft_index_t leader_commit,
    int rsp_success, raft_index_t rsp_current_idx, raft_index_t rsp_first_idx)
{
	return raft_server_async_append_entries_finish((raft_server_private_t *)me, node, can_update_commit, leader_commit,
    rsp_success, rsp_current_idx, rsp_first_idx);
}

int raft_async_retain_entries_finish(raft_server_t *me, int result, int n_entries, void *usr)
{
	return raft_server_async_retain_entries_finish((raft_server_private_t *)me, result, n_entries, usr);
}

raft_index_t raft_dispose_entries_cache(raft_server_t *me, bool ok, raft_batch_t *bat, raft_index_t idx)
{
return raft_server_dispose_entries_cache((raft_server_private_t *)me, ok, bat, idx);
}

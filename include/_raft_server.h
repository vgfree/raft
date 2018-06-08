#ifndef _RAFT_SERVER_H_
#define _RAFT_SERVER_H_

#include "raft_types.h"

typedef struct
{
    /* Persistent state: */

    /* the server's best guess of what the current term is
     * starts at zero */
    raft_term_t             current_term;

    /* The candidate the server voted for in its current term,
     * or Nil if it hasn't voted for any.  */
    raft_node_id_t          voted_for;

    /* the log which is replicated */
    raft_cache_private_t    *log;

    /* Volatile state: */

    /* idx of highest log entry known to be committed */
    raft_index_t            commit_idx;

    /* idx of highest log entry applied to state machine */
    raft_index_t            last_applied_idx;
    raft_index_t            last_applying_idx;

    /* follower/leader/candidate indicator */
    int                     state;

    /* amount of time left till timeout */
    int                     timeout_elapsed;

    raft_node_t             *nodes;
    int                     num_nodes;

    int                     election_timeout;
    int                     election_timeout_rand;
    int                     request_timeout;

    /* what this node thinks is the node ID of the current leader, or NULL if
     * there isn't a known current leader. */
    raft_node_t             *current_leader;

    /* callbacks */
    raft_cbs_t              cb;
    void                    *udata;

    /* my node ID */
    raft_node_t             *node;

    /* the log which has a voting cfg change, otherwise -1 */
    raft_index_t            voting_cfg_change_log_idx;

    int                     append_evts;

    /* Our membership with the cluster is confirmed (ie. configuration log was
     * committed) */
    enum
    {
        RAFT_NODE_STATUS_DISCONNECTED,
        RAFT_NODE_STATUS_CONNECTED,
        RAFT_NODE_STATUS_CONNECTING,
        RAFT_NODE_STATUS_DISCONNECTING
    }                       connected;

    int                     snapshot_in_progress;

    /* Last compacted snapshot */
    raft_index_t            snapshot_last_idx;
    raft_term_t             snapshot_last_term;
} raft_server_private_t;

raft_server_private_t *raft_server_new(void);

void raft_server_free(raft_server_private_t *me);

void raft_server_set_callbacks(raft_server_private_t *me, raft_cbs_t *funcs, void *udata);

raft_node_t *raft_server_add_node(raft_server_private_t *me, void *udata, raft_node_id_t id, int is_self);

raft_node_t *raft_server_add_non_voting_node(raft_server_private_t *me, void *udata, raft_node_id_t id, int is_self);

void raft_server_remove_node(raft_server_private_t *me, raft_node_id_t id);

raft_node_t *raft_server_get_node(raft_server_private_t *me, raft_node_id_t nodeid);

raft_node_id_t raft_server_get_my_nodeid(raft_server_private_t *me);

raft_node_t *raft_server_get_my_node(raft_server_private_t *me);

int raft_server_get_num_nodes(raft_server_private_t *me);

int raft_server_get_num_voting_nodes(raft_server_private_t *me);

raft_node_t *raft_server_get_node_by_idx(raft_server_private_t *me, const int idx);

raft_node_id_t raft_server_get_current_leader(raft_server_private_t *me);

raft_node_t *raft_server_get_current_leader_node(raft_server_private_t *me);

void *raft_server_get_udata(raft_server_private_t *me);

void raft_server_set_election_timeout(raft_server_private_t *me, int millisec);

int raft_server_get_election_timeout(raft_server_private_t *me);

void raft_server_set_request_timeout(raft_server_private_t *me, int millisec);

int raft_server_get_request_timeout(raft_server_private_t *me);

int raft_server_get_timeout_elapsed(raft_server_private_t *me);

/** Become leader
 * WARNING: this is a dangerous function call. It could lead to your cluster
 * losing it's consensus guarantees. */
void raft_server_become_leader(raft_server_private_t *me);

/** Become follower. This may be used to give up leadership. It does not change
 * currentTerm. */
void raft_server_become_follower(raft_server_private_t *me);

int raft_server_become_candidate(raft_server_private_t *me);

void raft_server_set_state(raft_server_private_t *me, int state);

int raft_server_get_state(raft_server_private_t *me);

int raft_server_is_follower(raft_server_private_t *me);

int raft_server_is_leader(raft_server_private_t *me);

int raft_server_is_candidate(raft_server_private_t *me);

int raft_server_set_current_term(raft_server_private_t *me, const raft_term_t term);

raft_term_t raft_server_get_current_term(raft_server_private_t *me);

/**
 * @return number of votes this server has received this election */
int raft_server_get_nvotes_for_me(raft_server_private_t *me);

/**
 * @return node ID of who I voted for */
raft_node_id_t raft_server_get_voted_for(raft_server_private_t *me);

int raft_server_set_voted_for(raft_server_private_t *me, const raft_node_id_t id);

raft_batch_t *raft_server_get_series_same_type_entries_from_idx(raft_server_private_t *me, raft_index_t idx);

raft_index_t raft_server_get_commit_idx(raft_server_private_t *me);

void raft_server_set_commit_idx(raft_server_private_t *me, raft_index_t idx);

/**
 * @return index of last applied entry */
raft_index_t raft_server_get_last_applied_idx(raft_server_private_t *me);

void raft_server_set_last_applied_idx(raft_server_private_t *me, raft_index_t idx);

/**
 * @return index of last applying entry */
raft_index_t raft_server_get_last_applying_idx(raft_server_private_t *me);

void raft_server_set_last_applying_idx(raft_server_private_t *me, raft_index_t idx);

/**
 * Delete all logs from this log onwards */
int raft_server_del_entries_after_from_idx(raft_server_private_t *me, raft_index_t idx);

/** Remove the first log entries.
 * This should be used for compacting logs.
 * @return 0 on success
 **/
int raft_server_del_entries_ahead_from_idx(raft_server_private_t *me, raft_index_t idx);

int raft_server_election_start(raft_server_private_t *me);

void raft_server_effect_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx);

void raft_server_revert_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx);

void raft_server_apply_cfg_entry(raft_server_private_t *me, raft_entry_t *ety, const raft_index_t idx);

/** Async apply all entries up to the commit index start function.
 * Apply entries from lastApplying + 1
 **/
int raft_server_async_apply_all_start(raft_server_private_t *me);

/** Async apply all entries up to the commit index finish function.
 * @return
 *  0 on success, entries committed;
 *  RAFT_ERR_SHUTDOWN when server MUST shutdown */
int raft_server_async_apply_all_finish(raft_server_private_t *me, bool ok, raft_batch_t *bat, raft_index_t idx);

void do_append_entries_cache(raft_server_private_t *me, bool ok, raft_batch_t *bat, raft_index_t idx);

int raft_server_async_append_entries_start(raft_server_private_t *me, raft_node_t *node, raft_batch_t *bat, raft_index_t idx,
    raft_index_t leader_commit, raft_index_t rsp_first_idx);

int raft_server_async_append_entries_finish(raft_server_private_t *me, raft_node_t *node, bool can_update_commit, raft_index_t leader_commit,
    int rsp_success, raft_index_t rsp_current_idx, raft_index_t rsp_first_idx);

int raft_server_send_requestvote(raft_server_private_t *me, raft_node_t *node);

int raft_server_send_appendentries(raft_server_private_t *me, raft_node_t *node);

int raft_server_send_appendentries_response(raft_server_private_t *me, raft_node_t *node, msg_appendentries_response_t *r);

int raft_server_periodic(raft_server_private_t *me, int msec_since_last_period);

int raft_server_recv_appendentries(
    raft_server_private_t   *me,
    raft_node_t             *node,
    msg_appendentries_t     *ae);

#endif /* ifndef _RAFT_SERVER_H_ */


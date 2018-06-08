#ifndef _RAFT_NODE_H_
#define _RAFT_NODE_H_

#include "raft_types.h"

typedef struct
{
    void            *udata;

    raft_index_t    next_idx;
    raft_index_t    match_idx;

    int             flags;

    raft_node_id_t  id;
} raft_node_private_t;

raft_node_private_t *raft_node_new(void *udata, raft_node_id_t id);

void raft_node_free(raft_node_private_t *me);

void raft_node_set_next_idx(raft_node_private_t *me, raft_index_t nextIdx);

void raft_node_set_match_idx(raft_node_private_t *me, raft_index_t matchIdx);

void raft_node_fix_vote_for_me(raft_node_private_t *me, const int vote);

int raft_node_has_vote_for_me(raft_node_private_t *me);

void raft_node_set_has_sufficient_logs(raft_node_private_t *me, const int has);

/** Check if a node has sufficient logs to be able to join the cluster.
**/
int raft_node_has_sufficient_logs(raft_node_private_t *me);

/** Check if a node is active.
 * Active nodes could become voting nodes.
 * This should be used for creating the membership snapshot.
 **/
int raft_node_is_active(raft_node_private_t *me);

/** Tell if a node is a voting node or not.
 * @return 1 if this is a voting node. Otherwise 0. */
int raft_node_is_voting(raft_node_private_t *me);

void raft_node_set_voting_committed(raft_node_private_t *me, int committed);

void raft_node_set_addition_committed(raft_node_private_t *me, int committed);

#endif /* ifndef _RAFT_NODE_H_ */


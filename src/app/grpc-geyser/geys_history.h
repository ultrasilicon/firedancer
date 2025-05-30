#ifndef HEADER_fd_src_app_geys_history_h
#define HEADER_fd_src_app_geys_history_h

#include "../../util/fd_util.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../discof/replay/fd_replay_notif.h"

struct geys_history_args {
  uint                 block_index_max;
  uint                 txn_index_max;
  uint                 acct_index_max;
  char                 history_file[ PATH_MAX ];

  /* Bump allocator */
  fd_spad_t *          spad;
};
typedef struct geys_history_args geys_history_args_t;

struct geys_history;
typedef struct geys_history geys_history_t;

struct geys_txn_key {
  ulong v[FD_ED25519_SIG_SZ / sizeof( ulong )];
};
typedef struct geys_txn_key geys_txn_key_t;

geys_history_t * geys_history_create(geys_history_args_t * args);

void geys_history_save(geys_history_t * hist, fd_blockstore_t * blockstore, fd_replay_notif_msg_t * msg);

ulong geys_history_first_slot(geys_history_t * hist);

ulong geys_history_latest_slot(geys_history_t * hist);

fd_replay_notif_msg_t * geys_history_get_block_info(geys_history_t * hist, ulong slot);

fd_replay_notif_msg_t * geys_history_get_block_info_by_hash(geys_history_t * hist, fd_hash_t * h);

uchar * geys_history_get_block(geys_history_t * hist, ulong slot, ulong * blk_sz);

uchar * geys_history_get_txn(geys_history_t * hist, geys_txn_key_t * sig, ulong * txn_sz, ulong * slot);

const void * geys_history_first_txn_for_acct(geys_history_t * hist, fd_pubkey_t * acct, geys_txn_key_t * sig, ulong * slot);

const void * geys_history_next_txn_for_acct(geys_history_t * hist, geys_txn_key_t * sig, ulong * slot, const void * iter);

#endif /* HEADER_fd_src_app_geys_history_h */

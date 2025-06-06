#ifndef HEADER_fd_src_app_geys_history_h
#define HEADER_fd_src_app_geys_history_h

#include "../../util/fd_util.h"

typedef struct fd_blockstore fd_blockstore_t;
typedef struct fd_replay_notif_msg fd_replay_notif_msg_t;
typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;
typedef struct geys_fd_ctx geys_fd_ctx_t;
struct fd_funk_private;
typedef struct fd_funk_private fd_funk_t;
struct geys_filter;
typedef struct geys_filter geys_filter_t;

struct geys_history_args {
  uint        block_index_max;
  uint        txn_index_max;
  uint        acct_index_max;
  char        history_file[ PATH_MAX ];

  fd_funk_t * funk;
  geys_filter_t * filt;

  /* Bump allocator */
  fd_spad_t * spad;
};
typedef struct geys_history_args geys_history_args_t;

struct geys_history;
typedef struct geys_history geys_history_t;

struct geys_txn_key {
  ulong v[64U / sizeof( ulong )];
};
typedef struct geys_txn_key geys_txn_key_t;

geys_history_t * geys_history_create(geys_history_args_t * args);

void geys_history_set_filter(geys_history_t * hist, geys_filter_t * filt);

void geys_history_save(geys_fd_ctx_t * fd, geys_history_t * hist, fd_blockstore_t * blockstore, fd_replay_notif_msg_t * msg);

ulong geys_history_first_slot(geys_history_t * hist);

ulong geys_history_latest_slot(geys_history_t * hist);

fd_replay_notif_msg_t * geys_history_get_block_info(geys_history_t * hist, ulong slot);

fd_replay_notif_msg_t * geys_history_get_block_info_by_hash(geys_history_t * hist, fd_hash_t * h);

uchar * geys_history_get_block(geys_history_t * hist, ulong slot, ulong * blk_sz);

uchar * geys_history_get_txn(geys_history_t * hist, geys_txn_key_t * sig, ulong * txn_sz, ulong * slot);

const void * geys_history_first_txn_for_acct(geys_history_t * hist, fd_pubkey_t * acct, geys_txn_key_t * sig, ulong * slot);

const void * geys_history_next_txn_for_acct(geys_history_t * hist, geys_txn_key_t * sig, ulong * slot, const void * iter);

#endif /* HEADER_fd_src_app_geys_history_h */

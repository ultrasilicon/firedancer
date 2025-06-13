#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../fd_flamenco_base.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../funk/fd_funk.h"

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"
#include "../fd_rwlock.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC 0X999999999UL

/* 12568 is size of map representation to store 301 hashes */
#define FD_BANK_BLOCK_HASH_QUEUE_SIZE (50000UL)
#define FD_BANK_CLOCK_TIMESTAMP_VOTES_SIZE (5000000UL)

/* fd_bank_t and fd_banks_t are used to manage the bank state in a
   fork-aware manner. */

struct fd_bank {
  /* Fields used for internal pool and bank management */
  ulong             slot;        /* slot this node is tracking, also the map key */
  ulong             next;        /* reserved for internal use by fd_pool_para, fd_map_chain_para and fd_banks_publish */
  ulong             parent_idx;  /* index of the parent in the node pool */
  ulong             child_idx;   /* index of the left-child in the node pool */
  ulong             sibling_idx; /* index of the right-sibling in the node pool */


  /* Simple or frequently modified fields that are always copied over */
  uchar                  block_hash_queue[FD_BANK_BLOCK_HASH_QUEUE_SIZE]__attribute__((aligned(128UL)));
  fd_fee_rate_governor_t fee_rate_governor;
  ulong                  capitalization;
  ulong                  lamports_per_signature;
  ulong                  prev_lamports_per_signature;
  ulong                  transaction_count;
  ulong                  parent_signature_cnt;
  ulong                  tick_height;
  ulong                  max_tick_height;
  ulong                  hashes_per_tick;
  uint128                ns_per_slot;
  ulong                  ticks_per_slot;
  ulong                  genesis_creation_time;
  double                 slots_per_year;
  fd_inflation_t         inflation;
  ulong                  total_epoch_stake;
  ulong                  eah_start_slot;
  ulong                  eah_stop_slot;
  ulong                  eah_interval;
  ulong                  block_height;
  fd_hash_t              epoch_account_hash;
  ulong                  execution_fees;
  ulong                  priority_fees;
  ulong                  signature_cnt;

  /* CoW Fields. These are only copied when explicitly requested by
     the caller. A lock is used to prevent contention between multiple
     threads trying to access the same field. */

  fd_rwlock_t            clock_timestamp_votes_lock;
  int                    clock_timestamp_votes_dirty;
  ulong                  clock_timestamp_votes_pool_idx;
};
typedef struct fd_bank fd_bank_t;


ulong
fd_bank_align( void );

ulong
fd_bank_footprint( void );

/* Clock Timestamp Votes Pool */

struct fd_bank_clock_timestamp_votes {
  ulong next;
  uchar votes[FD_BANK_CLOCK_TIMESTAMP_VOTES_SIZE]__attribute__((aligned(128UL)));
};
typedef struct fd_bank_clock_timestamp_votes fd_bank_clock_timestamp_votes_t;

#define POOL_NAME fd_bank_clock_timestamp_votes_pool
#define POOL_T    fd_bank_clock_timestamp_votes_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

/* Banks **************************************************************/

#define POOL_NAME fd_banks_pool
#define POOL_T    fd_bank_t
#include "../../util/tmpl/fd_pool.c"
#undef POOL_NAME
#undef POOL_T

#define MAP_NAME  fd_banks_map
#define MAP_ELE_T fd_bank_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"
#undef MAP_NAME
#undef MAP_ELE_T
#undef MAP_KEY

struct fd_banks {
  ulong           magic;     /* ==FD_BANKS_MAGIC */
  ulong           max_banks; /* Maximum number of banks */
  ulong           root;      /* root slot */
  ulong           root_idx;  /* root idx */

  fd_bank_t *                       pool;                       /* local join of pool */
  fd_banks_map_t *                  map;                        /* local join of map */
  fd_bank_clock_timestamp_votes_t * clock_timestamp_votes_pool; /* local join of clock vote timestamps pool */
};
typedef struct fd_banks fd_banks_t;

/* Bank accesssors */

fd_clock_timestamp_votes_global_t *
fd_bank_clock_timestamp_votes_query( fd_banks_t * banks, fd_bank_t * bank );

fd_clock_timestamp_votes_global_t *
fd_bank_clock_timestamp_votes_modify( fd_banks_t * banks, fd_bank_t * bank );

/* Banks accesssors */

FD_FN_PURE static inline fd_bank_t const *
fd_banks_root( fd_banks_t const * banks ) {
  return fd_banks_pool_ele_const( banks->pool, banks->root_idx );
}

ulong
fd_banks_align( void );

ulong
fd_banks_footprint( ulong max_banks );

void *
fd_banks_new( void * mem, ulong max_banks );

fd_banks_t *
fd_banks_join( void * mem );

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks, ulong slot );

fd_bank_t *
fd_banks_get_bank( fd_banks_t * banks, ulong slot );

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        slot,
                            ulong        parent_slot );

fd_bank_t const *
fd_banks_publish( fd_banks_t * banks, ulong slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_mgr_h */

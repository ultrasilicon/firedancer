#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_h

#include "../fd_flamenco_base.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../funk/fd_funk.h"

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"

FD_PROTOTYPES_BEGIN

#define FD_BANKS_MAGIC 0X999999999UL

/* 12568 is size of map representation to store 301 hashes */
#define FD_BANK_BLOCK_HASH_QUEUE_SIZE (50000UL)

struct fd_bank {
  ulong             slot;        /* slot this node is tracking, also the map key */
  ulong             next;        /* reserved for internal use by fd_pool_para, fd_map_chain_para and fd_banks_publish */
  ulong             parent_idx;  /* index of the parent in the node pool */
  ulong             child_idx;   /* index of the left-child in the node pool */
  ulong             sibling_idx; /* index of the right-sibling in the node pool */

  uchar             block_hash_queue[FD_BANK_BLOCK_HASH_QUEUE_SIZE]__attribute__((aligned(128UL)));

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
};
typedef struct fd_bank fd_bank_t;

ulong
fd_bank_align( void );

ulong
fd_bank_footprint( void );

#define POOL_NAME  fd_banks_pool
#define POOL_T fd_bank_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_banks_map
#define MAP_ELE_T fd_bank_t
#define MAP_KEY   slot
#include "../../util/tmpl/fd_map_chain.c"

struct fd_banks {
  ulong           magic;     /* ==FD_BANKS_MAGIC */
  ulong           max_banks; /* Maximum number of banks */
  ulong           root;      /* root slot */
  ulong           root_idx;  /* root idx */

  fd_bank_t *      pool;     /* local join of pool */
  fd_banks_map_t * map;      /* local join of map */
};
typedef struct fd_banks fd_banks_t;

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

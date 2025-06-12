#include "fd_snapshot_messages.h"
#include "../../flamenco/types/fd_types.h"

static void
fd_snapshot_manifest_init_blockhash_queue( fd_snapshot_manifest_t * snapshot_manifest,
                                           fd_solana_manifest_t *   solana_manifest ) {
  snapshot_manifest->bank.blockhash_queue.last_hash_index = solana_manifest->bank.blockhash_queue.last_hash_index;
  snapshot_manifest->bank.blockhash_queue.has_last_hash   = !!solana_manifest->bank.blockhash_queue.last_hash;
  if( solana_manifest->bank.blockhash_queue.last_hash ) {
    fd_memcpy( snapshot_manifest->bank.blockhash_queue.last_hash, &solana_manifest->bank.blockhash_queue.last_hash, HASH_SIZE );
  }

  ulong hashes_len = solana_manifest->bank.blockhash_queue.ages_len;
  fd_memcpy( snapshot_manifest->bank.blockhash_queue.hashes,
    &solana_manifest->bank.blockhash_queue.ages,
    sizeof(fd_snapshot_manifest_blockhash_t)*hashes_len );

  snapshot_manifest->bank.blockhash_queue.hashes_len = hashes_len;
  snapshot_manifest->bank.blockhash_queue.max_age    = solana_manifest->bank.blockhash_queue.max_age;
}

static void
fd_snapshot_manifest_init_bank_hash_info( fd_snapshot_manifest_t * snapshot_manifest,
                                          fd_solana_manifest_t *   solana_manifest ) {
  fd_memcpy( snapshot_manifest->bank.bank_hash_info.accounts_delta_hash,
             &solana_manifest->accounts_db.bank_hash_info.accounts_delta_hash, HASH_SIZE );
  fd_memcpy( snapshot_manifest->bank.bank_hash_info.accounts_hash,
             &solana_manifest->accounts_db.bank_hash_info.accounts_hash, HASH_SIZE );
  snapshot_manifest->bank.bank_hash_info.stats.num_updated_accounts    = solana_manifest->accounts_db.bank_hash_info.stats.num_updated_accounts;
  snapshot_manifest->bank.bank_hash_info.stats.num_removed_accounts    = solana_manifest->accounts_db.bank_hash_info.stats.num_removed_accounts;
  snapshot_manifest->bank.bank_hash_info.stats.num_lamports_stored     = solana_manifest->accounts_db.bank_hash_info.stats.num_lamports_stored;
  snapshot_manifest->bank.bank_hash_info.stats.total_data_len          = solana_manifest->accounts_db.bank_hash_info.stats.total_data_len;
  snapshot_manifest->bank.bank_hash_info.stats.num_executable_accounts = solana_manifest->accounts_db.bank_hash_info.stats.num_executable_accounts;
}

static void
fd_snapshot_manifest_init_ancestors( fd_snapshot_manifest_t * snapshot_manifest,
                                     fd_solana_manifest_t *   solana_manifest ) {
  ulong ancestors_len = solana_manifest->bank.ancestors_len;
  ulong ancestors_max_capacity = sizeof(snapshot_manifest->bank.ancestors) / sizeof(fd_snapshot_manifest_ancestors_entry_t);
  if( ancestors_len > ancestors_max_capacity ) {
    FD_LOG_ERR(( "ancestors out of bounds with value %lu", ancestors_len ));
  }
  snapshot_manifest->bank.ancestors_len = ancestors_len;
  fd_memcpy( snapshot_manifest->bank.ancestors,
             solana_manifest->bank.ancestors,
             sizeof(fd_snapshot_manifest_ancestors_entry_t)*ancestors_len );
}

static void
fd_snapshot_manifest_init_hard_forks( fd_snapshot_manifest_t * snapshot_manifest,
                                      fd_solana_manifest_t *   solana_manifest) {
  ulong hard_forks_len = solana_manifest->bank.hard_forks.hard_forks_len;
  ulong hard_forks_max_capacity = sizeof(snapshot_manifest->bank.hard_forks) / sizeof(fd_snapshot_manifest_hard_fork_entry_t);
  if( hard_forks_len > hard_forks_max_capacity ) {
    FD_LOG_ERR(( "hard_forks_len out of bounds with value %lu", hard_forks_len ));
  }
  snapshot_manifest->bank.hard_forks_len = hard_forks_len;
  fd_memcpy( snapshot_manifest->bank.hard_forks,
             solana_manifest->bank.hard_forks.hard_forks,
             sizeof(fd_snapshot_manifest_ancestors_entry_t)*hard_forks_len );
}

static void
fd_snapshot_manifest_init_stakes( fd_snapshot_manifest_t * snapshot_manifest,
                                  fd_solana_manifest_t *   solana_manifest ) {
  /* TODO: deserialize the vote account state from vote accounts in solana manifest */
}

static void
fd_snapshot_manifest_init_bank( fd_snapshot_manifest_t * snapshot_manifest,
                                fd_solana_manifest_t *   solana_manifest ) {
  snapshot_manifest->bank.slot        = solana_manifest->bank.slot;
  snapshot_manifest->bank.parent_slot = solana_manifest->bank.parent_slot;
  snapshot_manifest->bank.epoch       = solana_manifest->bank.epoch;
  fd_memcpy( snapshot_manifest->bank.bank_hash, &solana_manifest->bank.hash, HASH_SIZE );
  fd_memcpy( snapshot_manifest->bank.parent_bank_hash, &solana_manifest->bank.parent_hash, HASH_SIZE );

  /* blockheight */
  snapshot_manifest->bank.block_height = solana_manifest->bank.block_height;

  fd_snapshot_manifest_init_bank_hash_info( snapshot_manifest, solana_manifest );
  fd_snapshot_manifest_init_blockhash_queue( snapshot_manifest, solana_manifest );
  fd_snapshot_manifest_init_ancestors( snapshot_manifest, solana_manifest );
  fd_snapshot_manifest_init_hard_forks( snapshot_manifest, solana_manifest );
  fd_snapshot_manifest_init_stakes( snapshot_manifest, solana_manifest );

}

static void
fd_snapshot_manifest_init_genesis( fd_snapshot_manifest_t * snapshot_manifest,
                                   fd_solana_manifest_t *   solana_manifest ) {
  snapshot_manifest->genesis.ticks_per_slot = solana_manifest->bank.ticks_per_slot;
  snapshot_manifest->genesis.creation_time  = solana_manifest->bank.genesis_creation_time;
  snapshot_manifest->genesis.has_hashes_per_tick = !!solana_manifest->bank.hashes_per_tick;
  if( solana_manifest->bank.hashes_per_tick ) {
    snapshot_manifest->genesis.hashes_per_tick = *solana_manifest->bank.hashes_per_tick;
  }
  snapshot_manifest->genesis.ns_per_slot               = solana_manifest->bank.ns_per_slot;
  snapshot_manifest->genesis.slots_per_year            = solana_manifest->bank.slots_per_year;

  /* inflation */
  snapshot_manifest->genesis.inflation.initial         = solana_manifest->bank.inflation.initial;
  snapshot_manifest->genesis.inflation.terminal        = solana_manifest->bank.inflation.terminal;
  snapshot_manifest->genesis.inflation.taper           = solana_manifest->bank.inflation.taper;
  snapshot_manifest->genesis.inflation.foundation      = solana_manifest->bank.inflation.foundation;
  snapshot_manifest->genesis.inflation.foundation_term = solana_manifest->bank.inflation.foundation_term;

  /* epoch schedule */
  snapshot_manifest->genesis.epoch_schedule.slots_per_epoch             = solana_manifest->bank.epoch_schedule.slots_per_epoch;
  snapshot_manifest->genesis.epoch_schedule.leader_schedule_slot_offset = solana_manifest->bank.epoch_schedule.leader_schedule_slot_offset;
  snapshot_manifest->genesis.epoch_schedule.warmup                      = solana_manifest->bank.epoch_schedule.warmup;
  snapshot_manifest->genesis.epoch_schedule.first_normal_epoch          = solana_manifest->bank.epoch_schedule.first_normal_epoch;
  snapshot_manifest->genesis.epoch_schedule.first_normal_slot           = solana_manifest->bank.epoch_schedule.first_normal_slot;

  /* fee rate governor */
  snapshot_manifest->genesis.fee_rate_governor.lamports_per_signature        = solana_manifest->bank.fee_calculator.lamports_per_signature;
  snapshot_manifest->genesis.fee_rate_governor.target_lamports_per_signature = solana_manifest->bank.fee_rate_governor.target_lamports_per_signature;
  snapshot_manifest->genesis.fee_rate_governor.target_signatures_per_slot    = solana_manifest->bank.fee_rate_governor.target_signatures_per_slot;
  snapshot_manifest->genesis.fee_rate_governor.min_lamports_per_signature    = solana_manifest->bank.fee_rate_governor.min_lamports_per_signature;
  snapshot_manifest->genesis.fee_rate_governor.burn_percent                  = solana_manifest->bank.fee_rate_governor.burn_percent;
}

fd_snapshot_manifest_t *
fd_snapshot_manifest_init_from_solana_manifest( void *                 mem,
                                                fd_solana_manifest_t * solana_manifest ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_snapshot_manifest_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_snapshot_manifest_t * snapshot_manifest = fd_type_pun( mem );

  snapshot_manifest->slot  = solana_manifest->bank.slot;
  snapshot_manifest->epoch = solana_manifest->bank.epoch;

  /* bank */
  fd_snapshot_manifest_init_bank( snapshot_manifest, solana_manifest );

  /* genesis */
  fd_snapshot_manifest_init_genesis( snapshot_manifest, solana_manifest );

  return snapshot_manifest;
}

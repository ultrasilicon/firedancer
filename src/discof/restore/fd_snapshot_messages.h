#ifndef HEADER_fd_src_discof_restore_fd_snapshot_messages_h
#define HEADER_fd_src_discof_restore_fd_snapshot_messages_h

#include "../../flamenco/types/fd_types_custom.h"
#include "../../ballet/lthash/fd_lthash.h"

#define HASH_SIZE 32UL

/* Stakes Definition ******************************************************** */

struct fd_snapshot_manifest_vote_lockout {
  ulong slot;

  /* Number of votes for this slot and subsequent slots that build off this slot.
     The confirmation count is used to calculate the number of lockout slots for
     which the validator cannot vote for another fork. */
  ulong confirmation_count;
};
typedef struct fd_snapshot_manifest_vote_lockout fd_snapshot_manifest_vote_lockout_t;

struct fd_snapshot_manifest_landed_vote { 
  uchar latency;
  fd_snapshot_manifest_vote_lockout_t lockout;
};
typedef struct fd_snapshot_manifest_landed_vote fd_snapshot_manifest_landed_vote_t;

struct fd_snapshot_manifest_authorized_voter {
  ulong epoch;

  uchar pubkey[ HASH_SIZE ];
};
typedef struct fd_snapshot_manifest_authorized_voter fd_snapshot_manifest_authorized_voter_t;

struct fd_snapshot_manifest_prior_voter {
  uchar pubkey[ HASH_SIZE ];
  ulong epoch_start;
  ulong epoch_end;
};
typedef struct fd_snapshot_manifest_prior_voter fd_snapshot_manifest_prior_voter_t;

struct fd_snapshot_manifest_prior_voters {
  ulong idx;
  uchar is_empty;
  fd_snapshot_manifest_prior_voter_t entries[ 32UL ];
};
typedef struct fd_snapshot_manifest_prior_voters fd_snapshot_manifest_prior_voters_t;

struct fd_snapshot_manifest_epoch_credits {
  ulong epoch;
  ulong credits;
  ulong prev_credits;
};
typedef struct fd_snapshot_manifest_epoch_credits fd_snapshot_manifest_epoch_credits_t;

struct fd_snapshot_manifest_block_timestamp {
  ulong slot;
  long  timestmap;
};
typedef struct fd_snapshot_manifest_block_timestamp fd_snapshot_manifest_block_timestamp_t;

struct fd_snapshot_manifest_vote_account_state {
  uchar node_pubkey[ HASH_SIZE ];

  uchar authorized_withdrawer[ HASH_SIZE ];

  uchar commission;

  ulong                              landed_votes_len;
  fd_snapshot_manifest_landed_vote_t landed_votes[ 64UL ];

  uchar has_root_slot;
  ulong root_slot;

  ulong                                   authorized_voters_len;
  fd_snapshot_manifest_authorized_voter_t authorized_voters[ 64UL ];

  /* A fixed size circular buffer of prior voters, which are
     represented by a voter pubkey and the range of epochs in which
     this vote account was active.
     TODO: this document was a guess */
  fd_snapshot_manifest_prior_voters_t prior_voters;

  ulong                                epoch_credits_len;
  fd_snapshot_manifest_epoch_credits_t epoch_credits[ 64UL ];

  fd_snapshot_manifest_block_timestamp_t block_timestamp;
};
typedef struct fd_snapshot_manifest_vote_account_state fd_snapshot_manifest_vote_account_state_t;

struct fd_snapshot_manifest_vote_account {
  /* pubkey of vote account */
  uchar pubkey[ HASH_SIZE ];

  fd_snapshot_manifest_vote_account_state_t vote_state;
};
typedef struct fd_snapshot_manifest_vote_account fd_snapshot_manifest_vote_account_t;

struct fd_snapshot_manifest_delegation {
  /* The voter pubkey to whom the stake is delegated */
  uchar voter_pubkey[ HASH_SIZE ];

  /* The activated stake amount */
  ulong stake;

  /* The activation epoch */
  ulong activation_epoch;

  /* The deactivateion epoch */
  ulong deactivation_epoch;

  /* The amoung of stake that can be activated per-epoch
     as a fraction of currently effective stake */
  double warmup_cooldown_rate;
};
typedef struct fd_snapshot_manifest_delegation fd_snapshot_manifest_delegation_t;

struct fd_snapshot_manifest_stake_delegation {
  uchar pubkey[ HASH_SIZE ];
  fd_snapshot_manifest_delegation_t delegation;
};
typedef struct fd_snapshot_manifest_stake_delegation fd_snapshot_manifest_stake_delegation_t;

struct fd_snapshot_manifest_stake_history_entry {
  /* The effective stake at this epoch */
  ulong effective;

  /* The sum of portion of stakes not fully warmed up */
  ulong activating;

  /* The portion of stakes requested to be cooled down, but not fully deactivated yet */
  ulong deactivating;
};
typedef struct fd_snapshot_manifest_stake_history_entry fd_snapshot_manifest_stake_history_entry_t;

struct fd_snapshot_manifest_stake_history {
  ulong epoch;
  fd_snapshot_manifest_stake_history_entry_t entry;
};
typedef struct fd_snapshot_manifest_stake_history fd_snapshot_manifest_stake_history_t;

struct fd_snapshot_manifest_stakes {
  /* TODO: docs */
  ulong                               vote_accounts_len;
  fd_snapshot_manifest_vote_account_t vote_accounts[ 64UL ];

  /* TODO: docs */
  ulong                                   stake_delegations_len;
  fd_snapshot_manifest_stake_delegation_t stake_delegations[ 64UL ];

  /* TODO: docs */
  ulong                                stake_history_len;
  fd_snapshot_manifest_stake_history_t stake_history[ 64UL ];
};
typedef struct fd_snapshot_manifest_stakes fd_snapshot_manifest_stakes_t;

/* Epoch Stakes Definition ******************************************************** */

struct fd_snapshot_manifest_pubkey {
  uchar pubkey[ HASH_SIZE ];
};
typedef struct fd_snapshot_manifest_pubkey fd_snapshot_manifest_pubkey_t;

struct fd_snapshot_manifest_node_info {
  /* vote accounts on this node */
  ulong                         vote_accounts_len;
  fd_snapshot_manifest_pubkey_t vote_accounts[ 64UL ];


  /* total stake on this node */
  ulong total_stake;
};
typedef struct fd_snapshot_manifest_node_info fd_snapshot_manifest_node_info_t;

struct fd_snapshot_manifest_epoch_authorized_voter_entry {
  uchar vote_account[ HASH_SIZE ];
  uchar authorized_voter[ HASH_SIZE ];
};
typedef struct fd_snapshot_manifest_epoch_authorized_voter_entry fd_snapshot_manifest_epoch_authorized_voter_entry_t;


struct fd_snapshot_manifest_epoch_stakes {
  /* The vote accounts state and stake accounts state for this epoch */
  fd_snapshot_manifest_stakes_t stakes;

  /* The total stake across all stake accounts
     TODO: this is just a guess */
  ulong total_stake;

  /* The vote accounts and total stake for each node */
  ulong                            nodes_len;
  fd_snapshot_manifest_node_info_t nodes[ 64UL ];

  /* A mapping from each vote account to its authorized voter pubkey */
  ulong                                               epoch_authorized_voters_len;
  fd_snapshot_manifest_epoch_authorized_voter_entry_t epoch_authorized_voters[ 64UL ];

};
typedef struct fd_snapshot_manifest_epoch_stakes fd_snapshot_manifest_epoch_stakes_t;

/* Bank Definition ******************************************************** */

struct fd_snapshot_manifest_inflation {
  /* Initial inflation percentage, from time=0 */
  double initial;

  /* Terminal inflation percentage, to time=INF */
  double terminal;

  /* Rate per year, at which inflation is lowered until reaching terminal
     i.e. inflation(year) == MAX(terminal, initial*((1-taper)^year)) */
  double taper;

  /* Percentage of total inflation allocated to the foundation */
  double foundation;

  /* Duration of foundation pool inflation, in years */
  double foundation_term;
};
typedef struct fd_snapshot_manifest_inflation fd_snapshot_manifest_inflation_t;

struct fd_snapshot_manifest_epoch_schedule {
  /* The maximum number of slots in each epoch. */
  ulong slots_per_epoch;

  /* A number of slots before beginning of an epoch to calculate
     a leader schedule for that epoch. */
  ulong leader_schedule_slot_offset;

  /* Whether epochs start short and grow. */
  uchar warmup;

  /* The first epoch after the warmup period.
     Calculated as log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH). */
  ulong first_normal_epoch;

  /* The first slot after the warmup period.
     Calculated as MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1). */
  ulong first_normal_slot;
};
typedef struct fd_snapshot_manifest_epoch_schedule fd_snapshot_manifest_epoch_schedule_t;

struct fd_snapshot_manifest_fee_rate_governor {
  /* The current cost of a signature  This amount may increase/decrease over time based on
     cluster processing load.*/
  ulong lamports_per_signature;

  /* The target cost of a signature when the cluster is operating around target_signatures_per_slot
     signatures */
  ulong target_lamports_per_signature;
  
  /* A threshold used to estimate the processing capacity of the cluster.  If the number of
     signatures for recent slots are fewer than this value, the lamports_per_signature cost will
     decrease for the next slot.  Likewise, if the number of signatures for recent slots are greater
     than this value, the lamports_per_signature cost will increase for the next slot */
  ulong target_signatures_per_slot;

  /* The minimum cost for a signature. */
  ulong min_lamports_per_signature;

  /* The maximum cost for a signature. */
  ulong max_lamports_per_signature;

  /* TODO: ?? */
  uchar burn_percent;
};
typedef struct fd_snapshot_manifest_fee_rate_governor fd_snapshot_manifest_fee_rate_governor_t;

struct fd_snapshot_manifest_genesis {

  /* Number of ticks per slot TODO: better docs */
  ulong ticks_per_slot;

  /* The unix timestamp when the genesis block was created */
  ulong creation_time;

  /* How many hashes to roll before emitting the next tick entry.
     Setting hashes_per_tick to none disables hashing. */
  uchar has_hashes_per_tick;
  ulong hashes_per_tick;

  /* The number of nanoseconds per slot, defined as
     tick_duration * ticks_per_slot. */
  uint128 ns_per_slot;

  /* The number of slots per year, defined as
     nanoseconds per year / (tick_duration * ticks_per_slot)*/
  double slots_per_year;

  /* Inflation configuration */
  fd_snapshot_manifest_inflation_t inflation;

  /* The epoch schedule controls how slots map to epochs */
  fd_snapshot_manifest_epoch_schedule_t epoch_schedule;

  /* Fee Rate Governor */
  fd_snapshot_manifest_fee_rate_governor_t fee_rate_governor;

};
typedef struct fd_snapshot_manifest_genesis fd_snapshot_manifest_genesis_t;

struct fd_snapshot_manifest_hash_info {
  /* The current cost of a signature. */
  ulong lamports_per_signature;

  /* The hash index is used to calculate the age of the hash.
     The hash's age is calculated as last_hash_index - hash_index */
  ulong hash_index;

  /* The timestamp of the hash */
  ulong timestamp;
};
typedef struct fd_snapshot_manifest_hash_info fd_snapshot_manifest_hash_info_t;

struct fd_snapshot_manifest_blockhash {
  uchar hash[ HASH_SIZE ];
  fd_snapshot_manifest_hash_info_t hash_info;
};
typedef struct fd_snapshot_manifest_blockhash fd_snapshot_manifest_blockhash_t;

struct fd_snapshot_manifest_blockhash_queue {
  /* The index of last hash to be registered */
  ulong last_hash_index;

  /* The last hash to be registered. May be empty. */
  uchar has_last_hash;
  uchar last_hash[ HASH_SIZE ];

  /* blockhash queue */
  ulong                            hashes_len;
  fd_snapshot_manifest_blockhash_t hashes[ 300UL ];

  /* The maximum age of a blockhash.  Blockhashes with ages older
     than this age will be dropped from the queue. */
  ulong max_age;
};
typedef struct fd_snapshot_manifest_blockhash_queue fd_snapshot_manifest_blockhash_queue_t;

struct fd_snapshot_manifest_ancestors_entry {
  /* The current slot number */
  ulong slot;

  /* A rolling bitfield that stores whether each slot represented in the bitfield
     is an ancestor of the current slot */
  ulong ancestors;
};
typedef struct fd_snapshot_manifest_ancestors_entry fd_snapshot_manifest_ancestors_entry_t;

struct fd_snapshot_manifest_hard_fork_entry {
  ulong slot;

  ulong fork_count;
};
typedef struct fd_snapshot_manifest_hard_fork_entry fd_snapshot_manifest_hard_fork_entry_t;

struct fd_snapshot_manifest_bank_hash_info_stats {
  ulong num_updated_accounts;
  ulong num_removed_accounts;
  ulong num_lamports_stored;
  ulong total_data_len;
  ulong num_executable_accounts;
};
typedef struct fd_snapshot_manifest_bank_hash_info_stats fd_snapshot_manifest_bank_hash_info_stats_t;

struct fd_snapshot_manifest_bank_hash_info {
  uchar accounts_delta_hash[ HASH_SIZE ];
  uchar accounts_hash[ HASH_SIZE ];
  fd_snapshot_manifest_bank_hash_info_stats_t stats;
};
typedef struct fd_snapshot_manifest_bank_hash_info fd_snapshot_manifest_bank_hash_info_t;

struct fd_snapshot_manifest_bank {
  /* The current slot number for this bank */
  ulong slot;

  /* The parent slot is the slot that this bank builds on top of.  It is
     typically slot-1, but can be an arbitrary amount of slots earlier
     in case of forks, when the block skips over preceding slots. */
  ulong parent_slot;

  /* The current epoch for this bank */
  ulong epoch;

  /* The bank hash of the slot represented by this snapshot.  The bank
     hash is used by the validator to detect mismatches.  All validators
     must agree on a bank hash for each slot or they will fork off. */
  uchar bank_hash[ HASH_SIZE ];

  /* The bank hash of the parent slot. */
  uchar parent_bank_hash[ HASH_SIZE ];

  /* The internal details of the bank hash, which includes the accounts_delta_hash
     and accounts_hash and a summary of acocunt changes */
  fd_snapshot_manifest_bank_hash_info_t bank_hash_info;

  /* The number of blocks that have been built since genesis.
     Each bank's block_height is 1 + its parent block_height */
  ulong block_height;

  /* The blockhash queue stores up to the last 300 blockhashes, which are
     Proof of History slot hashes. Blockhashes are used to expire transactions.
     If a transaction's recent blockhash is older than the last 150 blockhashes,
     it is expired. */
  fd_snapshot_manifest_blockhash_queue_t blockhash_queue;

  /* The ancestor slots of this bank.
     TODO: better docs */
  ulong                                  ancestors_len;
  fd_snapshot_manifest_ancestors_entry_t ancestors[ 64UL ];

  /* The hard forks tracks slots where hard forks have occurred and how many
     have occurred. */
  ulong                                  hard_forks_len;
  fd_snapshot_manifest_hard_fork_entry_t hard_forks[ 64UL ];

  /* The cached stakes for this bank.  Stakes track vote account state and stake account state
     for the fork this bank is on. */
  fd_snapshot_manifest_stakes_t stakes;

  /* The pubkey to send transactions fees to. */
  uchar collector_id[ HASH_SIZE ];

  /* Fees that have been collected by this bank */
  ulong collector_fees;

  /* Rent that has been collected */
  ulong collected_rent;

  /* The number of committed transactions since genesis */
  ulong transaction_count;

  /* The number of signatures from valid transactions in this slot */
  ulong signature_count;

  /* The number of ticks that have passed since the genesis block.  Each tick is
     is verified by Proof of History hashing. */
  ulong tick_height;

  /* The maximum tick height for this bank, calculated as
     (slot + 1) * ticks_per_slot. */
  ulong max_tick_height;

  /* The total number of lamports across all accounts, which is 
     used to calculate inflation. */
  ulong capitalization;

  /* The total size in bytes of all account data on chain.
     This value is updated by the bank when changes to accounts are made. */
  ulong accounts_data_len;

  /* A boolean reflecting whether any entries were recorded into the PoH
     stream for the slot == self.slot
     TODO: better docs */
  uchar is_delta;
};
typedef struct fd_snapshot_manifest_bank fd_snapshot_manifest_bank_t;

/* Manifest Definition ******************************************************** */

struct fd_snapshot_manifest_incremental_snapshot_info {
  /* The slot at the full snapshot */
  ulong full_slot;

  /* The hash of the full snapshot */
  uchar full_hash[ HASH_SIZE ];

  /* The capitalization of the full snapshot */
  ulong full_capitalization;

  /* The hash of the incremental snapshot */
  uchar incremental_hash[ HASH_SIZE ];

  /* The capitalization of the incremental snapshot */
  ulong incremental_capitalization;
};
typedef struct fd_snapshot_manifest_incremental_snapshot_info fd_snapshot_manifest_incremental_snapshot_info_t;

struct fd_snapshot_manifest {
  /* The current slot number for this snapshot */
  ulong slot;

  /* The current epoch for this snapshot */
  ulong epoch;

  /* The current bank state at this snapshot slot */
  fd_snapshot_manifest_bank_t bank;

  /* Each Solana cluster (mainnet, testnet, devnet, ..) is configured at
     genesis with certain parameters, which cannot be changed.  These
     parameters include the inflation, epoch schedule, fee rate governor etc. */
  fd_snapshot_manifest_genesis_t genesis;

  /* If the snapshot is an incremental snapshot, then the
     incremental_snapshot_info will be populated so that
     validators can verify the incremental snapshot builds off
     their corresponding full snapshot. */
  uchar has_incremental_snapshot_info;
  fd_snapshot_manifest_incremental_snapshot_info_t incremental_snapshot_info;

  /* The hash of all accounts at this snapshot's epoch */
  uchar has_epoch_account_hash;
  uchar epoch_account_hash[ HASH_SIZE ];

  /* Epoch stakes represent the exact amount staked to each pubkey for
     each of the current, previous, and previous before that epochs.
     They are primarily used to derive the leader schedule.  There are
     almost always 3 epoch stakes, except in certain cases where the
     chain is close to genesis, when there might only be 1 or 2. */
  ulong                               epoch_stakes_len;
  fd_snapshot_manifest_epoch_stakes_t epoch_stakes[ 3UL ];

  /* TODO: Document.  Not enabled yet? */
  uchar has_lthash;
  uchar lthash[ 2048UL ];
};

typedef struct fd_snapshot_manifest fd_snapshot_manifest_t;

/* Forward Declarations */

typedef struct fd_solana_manifest fd_solana_manifest_t;

FD_PROTOTYPES_BEGIN

fd_snapshot_manifest_t *
fd_snapshot_manifest_init_from_solana_manifest( void *                 mem,
                                                fd_solana_manifest_t * solana_manifest );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_messages_h */

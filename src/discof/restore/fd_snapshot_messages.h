#ifndef HEADER_fd_src_discof_restore_fd_snapshot_messages_h
#define HEADER_fd_src_discof_restore_fd_snapshot_messages_h

#include "../../flamenco/types/fd_types_custom.h"
#include "../../ballet/lthash/fd_lthash.h"

struct fd_snapshot_manifest_vote_account {
  /* The pubkey of the vote account */
  uchar vote_account_pubkey[ 32UL ];

  /* The percent of inflation rewards earned by the validator and
     deposited into the validator's vote account, from 0 to 100%.
     The remaning percentage of inflation rewards is distributed to
     all delegated stake accounts by stake weight. */
  uchar commission;

  /* The epoch credits array tracks the history of how many credits the
     provided vote account earned in each of the past epochs.  The
     entry at epoch_credits[0] is for the current epoch,
     epoch_credits[1] is for the previous epoch, and so on.  In cases of
     booting a new chain from genesis, or for new vote accounts the
     epoch credits history may be short. */
  ulong epoch_credits_history_len;
  ulong epoch_credits[ 64UL ]; /* TODO: Bound correctly */
};

typedef struct fd_snapshot_manifest_vote_account fd_snapshot_manifest_vote_account_t;

struct fd_snapshot_manifest_stake_delegation {
  /* The stake account pubkey */
  uchar stake_account_pubkey[ 32UL ];

  /* The voter pubkey to whom the stake is delegated */
  uchar vote_account_pubkey[ 32UL ];

  /* The activated stake amount that is delegated */
  ulong stake;
};

typedef struct fd_snapshot_manifest_stake_delegation fd_snapshot_manifest_stake_delegation_t;

struct fd_snapshot_manifest_inflation_params {
  /* The initial inflation percentage starting at genesis.
     This value is set at genesis to 8% and is not expected to change. */
  double initial;

  /* The terminal inflation percentage is the long-term steady state
     inflation rate after a period of disinflation.  This value is set
     at genesis to 1.5% and is not expected to change. */
  double terminal;

  /* The rate per year at which inflation is lowered until it reaches
     the terminal inflation rate.  This value is set to 15% at genesis
     and is not expected to change. */
  double taper;

  /* The percentage of total inflation allocated to the foundation.
     This value is set at genesis to 5% and is not expected to change. */
  double foundation;

  /* The number of years in which a portion of the total inflation is 
     allocated to the foundation (see foundation field).  This value is
     set to 7 years at genesis and is not expected to change. */
  double foundation_term;
};

typedef struct fd_snapshot_manifest_inflation_params fd_snapshot_manifest_inflation_params_t;

struct fd_snapshot_manifest_epoch_schedule_params {
  /* The maximum number of slots in each epoch. */
  ulong slots_per_epoch;

  /* A number of slots before beginning of an epoch to calculate a
     leader schedule for that epoch.  This value is set to
     slots_per_epoch (basically one epoch) and is unlikely to change. */
  ulong leader_schedule_slot_offset;

  /* Whether there is a warmup period where epochs are short and grow by
     powers of two until they reach the default epoch length of
     slots_per_epoch.  This value is set by default to true at genesis,
     though it may be configured differently in development
     environments. */
  uchar warmup;
};

typedef struct fd_snapshot_manifest_epoch_schedule_params fd_snapshot_manifest_epoch_schedule_params_t;

struct fd_snapshot_manifest_fee_rate_governor {
  /* Transaction fees are calculated by charging a cost for each
     signature.  There is a mechanism to dynamically adjust the cost per
     signature based on the cluster's transaction processing capacity.
     In this mechanism, the cost per signature can vary between 50% to
     1000% of the target_lamports_per_signature value, which is the cost
     per signature when the cluster is operating at the desired
     transaction processing capacity defined by
     target_signatures_per_slot.

     This value is fixed at 10,000 from genesis onwards but may be
     changed in the future with feature flags. */
  ulong target_lamports_per_signature;

  /* The cluster transaction processing capacity is measured by
     signatures per slot.  Solana defines the desired transaction
     processing capacity using the value target_signatures_per_slot.

     This value is fixed at 20,000 from genesis onwards but may be
     changed in the future with feature flags. */
  ulong target_signatures_per_slot;

  /* The minimum cost per signature is 50% of the
     target_lamports_per_signature value.  Under the current default for
     target_lamports_per_signature, this value is at 5,000 lamports per
     signature. */
  ulong min_lamports_per_signature;

  /* The maximum cost per signature is 1000% of the
     target_lamports_per_signature value.  Under the current default for
     target_lamports_per_signature, this value is at 100,000 lamports
     per signature.*/
  ulong max_lamports_per_signature;

  /* The percent of collected fees that are burned.  This value is
     currently set to a fixed value of 50% from genesis onwards, but
     may be changed in the future with feature flags. */
  uchar burn_percent;
};

typedef struct fd_snapshot_manifest_fee_rate_governor fd_snapshot_manifest_fee_rate_governor_t;

struct fd_snapshot_manifest_incremental_snapshot_info {
  /* An incremental snapshot is built on top of a full snapshot at some
     reference slot.  The incremental snapshot then just contains
     account state deltas since the reference slot. */
  ulong full_snapshot_slot;

  /* The accounts hash of the full snapshot */
  uchar full_snapshot_accounts_hash[ 32UL ];

  /* An incremental snapshot only contains the capitalization of
     accounts that are modified between the slot range
     [full_snapshot_slot, incremental_snapshot_slot].  When the
     validator loads an incremental snapshot, it verifies the
     full_snapshot_capitalization field matches the capitalization from
     its previously loaded full snapshot. */
  ulong full_snapshot_capitalization;

  /* An incremental snapshot accounts hash only contains modified
     accounts within the slot range [full_snapshot_slot,
     incremental_snapshot_slot].

     When loading an incremental snapshot, the validator calculates its
     own incremental_accounts_hash and ensures it matches the given
     incremental_accounts_hash */
  uchar incremental_accounts_hash[ 32UL ];

  /* The incremental capitalization is the capitalization of all
     accounts in the incremental_accounts_hash (modified accounts within
     the slot range [full_snapshot_slot, incremental_snapshot_slot]).

     Validators verify the given incremental_accounts_hash and
     incremental_capitalization matches their calculated
     incremental_accounts_hash and incremental_capitalization.

     The incremental_capitalization is not the same as the
     capitalization field from the snapshot_manifest message.  The
     capitalization field is the capitalization of all accounts at the
     snapshot slot. */
  ulong incremental_capitalization;
};

typedef struct fd_snapshot_manifest_incremental_snapshot_info fd_snapshot_manifest_incremental_snapshot_info_t;

struct fd_snapshot_manifest {
  /* The UNIX timestamp when the genesis block was for this chain
     was created, in nanoseconds.  */
  /* TODO: convert from seconds */
  long creation_time_ns;

  /* At genesis, certain parameters can be set which control the
    inflation rewards going forward.  This includes what the initial
    inflation is and how the inflation curve changes over time.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_inflation_params_t inflation_params;

  /* At genesis, certain parameters can be set which control the
     epoch schedule going forward.  This includes how many slots
     there are per epoch, and certain development settings like if
     epochs start short and grow longer as the chain progreses.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_epoch_schedule_params_t epoch_schedule_params;

  /* At genesis, certain parameters can be set which control
     how transaction fees are dynamically adjusted going forward.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_fee_rate_governor_t fee_rate_governor;

  /* A snapshot is either a full snapshot, or an incremental snapshot.
     A full snapshot contains account state for every account in the
     ledger, while an incremental one just contains the account state
     delta since some prior reference slot. */
  int is_incremental;

  /* If the snapshot is an incremental snapshot, then the
     incremental_snapshot_info will be populated so that the validator
     can verify the incremental snapshot builds off their corresponding
     full snapshot.  If the snapshot is not an incremental snapshot, the
     values in the incremental snapshot info are undefined. */
  fd_snapshot_manifest_incremental_snapshot_info_t incremental_snapshot_info;

  /* The current slot number for this snapshot */
  ulong slot;

  /* The number of blocks that have been built since genesis.  This is
     kind of like the slot number, in that it increments by 1 for every
     landed block, but it does not increment for skipped slots, so the
     block_height will always be less than or equal to the slot. */
  ulong block_height;

  /* The parent slot is the slot that this block builds on top of.  It
     is typically slot-1, but can be an arbitrary amount of slots
     earlier in case of forks, when the block skips over preceding
     slots. */
  ulong parent_slot;

  /* The bank hash of the slot represented by this snapshot.  The bank
     hash is used by the validator to detect mismatches.  All validators
     must agree on a bank hash for each slot or they will fork off. */
  uchar bank_hash[ 32UL ];

  /* The merkle-based hash of all account state on chain at the slot the
     snapshot is created. */
  uchar accounts_hash[ 32UL ];

  /* The merkle-based hash of modified accounts for the slot the
     snapshot is created. */
  uchar accounts_delta_hash[ 32UL ];

  /* The lattice hash of all account state on chain.  The lattice hash
     is more scalable than the previous merkle-based accounts_hash
     and accounts_delta_hash because the hash can be calculated
     incrementally without the need to sort all accounts.

     The lattice hash will replace the merkle-based accounts_hash and
     accounts_delta_hash. When the lattice hash is activated, each bank
     hash will include the lattice hash of all account state. */
  int has_accounts_lthash;
  uchar accounts_lthash[ 2048UL ];

  /* The bank hash of the parent slot. */
  uchar parent_bank_hash[ 32UL ];

  /* The hash of all accounts at this snapshot's epoch */
  int   has_epoch_account_hash;
  uchar epoch_account_hash[ 32UL ];

  /* The proof of history component "proves" the passage of time (see
     extended discussion in PoH tile for what that acutally means) by
     continually doing sha256 hashes.  A certain number of hashes are
     required to be in each slot, to prove the leader spent some amount
     of time on the slot and didn't end it too early.

     In all clusters and environments that matter, this value is fixed
     at 64 and is unlikely to change, however it might be configured
     differently in development environments. */
  ulong ticks_per_slot;

  /* The proof of history component typically requires every block to
     have 64 "ticks" in it (although this is configurable during
     development), but each tick is some flexible number of recursive
     sha256 hashes defined at genesis.

     The number of hashes for mainnet genesis is 12,500, meaning there
     will be 800,000 hashes per slot.

     There are various features, named like update_hashes_per_tick*
     which if enabled update the hashes_per_tick of the chain as-of the
     epoch where they are enabled.  This value incorporates any changes
     due to such features.

     In development environments, sometimes hashes_per_tick will not be
     specified (has_hashes_per_tick will be 0).  Agave refers to this as
     a "low power" mode, where ticks have just one hash in them.  It is
     distinct from just setting hahes_per_tick to 1, because it also
     reduces the slot duration from 400ms down to 0ms (or however long
     it takes to produce the hash).  See comments in the PoH tile for
     more extended discussion. */
  int   has_hashes_per_tick;
  ulong hashes_per_tick;

  /* The total number of lamports across all accounts at this snapshot's
     slot.*/
  ulong capitalization;

  /* A list of this epoch's vote accounts and their state relating to
     rewards distribution, which includes the vote account's commission
     and vote credits.

     The validator distributes vote and stake rewards for the previous
     epoch in the slots immediately after the epoch boundary.  These
     vote and stake rewards are calculated as a stake-weighted
     percentage of the inflation rewards for the epoch and validator
     uptime, which is measured by vote account vote credits. */
  ulong                               vote_accounts_len;
  fd_snapshot_manifest_vote_account_t vote_accounts[ 64UL ]; /* TODO: Bound correctly */

  /* Epoch stakes represent the exact amount staked to each pubkey for
     each of the current, previous, and previous before that epochs.
     They are primarily used to derive the leader schedule.  Three are
     required because
     
       E-2 - We need epoch stakes from two epochs ago to calculate the
             leader schedule for the current epoch E.
       E-1 - We need epoch stakes from one epoch ago to calculate the
             leader schedule for the next epoch E+1.
       E   - We need epoch stakes for the current epoch, which we will
             then incrementally update as the epoch continues, to
             eventually (when the epoch finishes) calculate the leader
             schedule for next next epoch E+2.
     
     The epoch stakes are stored in an array, where epoch_stakes[0] is
     the list of current epoch stakes, and epoch_stakes[1] is for the
     previous epoch, and so on.  There are almost always 3 epoch stakes,
     except in certain cases where the chain is close to genesis, when
     there might only be 1 or 2. */
  ulong                                   epoch_stakes_len;
  fd_snapshot_manifest_stake_delegation_t epoch_stakes[ 3UL ][ 64UL ]; /* TODO: Bound correctly */
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

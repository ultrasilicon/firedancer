#include "fd_exec_epoch_ctx.h"
#include <assert.h>
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../fd_runtime_public.h"
#include "../fd_bank_mgr.h"

/* TODO remove this */
#define MAX_LG_SLOT_CNT   10UL

ulong
fd_exec_epoch_ctx_align( void ) {
  return FD_EXEC_EPOCH_CTX_ALIGN;
}

void *
fd_exec_epoch_ctx_new( void * mem,
                       ulong  vote_acc_max ) {
  (void)vote_acc_max;
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem %lu", (ulong)mem ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * self = mem;
  fd_memset( self, 0, sizeof(fd_exec_epoch_ctx_t) );

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_EPOCH_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * ctx = (fd_exec_epoch_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_epoch_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * hdr = (fd_exec_epoch_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

void
fd_exec_epoch_ctx_bank_mem_clear( fd_exec_epoch_ctx_t * epoch_ctx ) {
  (void)epoch_ctx;

  // {
  //   fd_delegation_pair_t_mapnode_t * old_pool = epoch_bank->stakes.stake_delegations_pool;
  //   fd_delegation_pair_t_mapnode_t * old_root = epoch_bank->stakes.stake_delegations_root;
  //   fd_delegation_pair_t_map_release_tree( old_pool, old_root );
  //   epoch_bank->stakes.stake_delegations_root = NULL;
  // }
  // {
  //   fd_vote_accounts_pair_t_mapnode_t * old_pool = epoch_bank->next_epoch_stakes.vote_accounts_pool;
  //   fd_vote_accounts_pair_t_mapnode_t * old_root = epoch_bank->next_epoch_stakes.vote_accounts_root;
  //   fd_vote_accounts_pair_t_map_release_tree( old_pool, old_root );
  //   epoch_bank->next_epoch_stakes.vote_accounts_root = NULL;
  // }
}

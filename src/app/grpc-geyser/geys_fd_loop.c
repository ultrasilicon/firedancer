#define _DEFAULT_SOURCE

#include "geys_fd_loop.h"
#include "geys_filter.h"
#include "../../funk/fd_funk_filemap.h"
#include "../../tango/fd_tango_base.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../discof/replay/fd_replay_notif.h"

#define SHAM_LINK_CONTEXT geys_fd_ctx_t
#define SHAM_LINK_STATE   fd_replay_notif_msg_t
#define SHAM_LINK_NAME    replay_sham_link
#include "sham_link.h"

struct geys_fd_ctx {
  fd_spad_t * spad;
  fd_funk_t funk_join[1];
  fd_funk_t * funk;
  fd_blockstore_t blockstore_ljoin;
  fd_blockstore_t * blockstore;
  replay_sham_link_t * rep_notify;
  geys_filter_t * filter;
};
typedef struct geys_fd_ctx geys_fd_ctx_t;

geys_fd_ctx_t *
geys_fd_init( geys_fd_loop_args_t * args ) {
  geys_fd_ctx_t * ctx = (geys_fd_ctx_t *)malloc(sizeof(geys_fd_ctx_t));
  memset( ctx, 0, sizeof(geys_fd_ctx_t) );

  FD_LOG_NOTICE(( "attaching to funk file \"%s\"", args->funk_file ));
  ctx->funk = fd_funk_open_file( ctx->funk_join, args->funk_file, 1, 0, 0, 0, 0, FD_FUNK_READONLY, NULL );
  if( !ctx->funk ) {
    FD_LOG_ERR(( "failed to join funk" ));
  }

  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", args->blockstore_wksp ));
  fd_wksp_t * wksp = fd_wksp_attach( args->blockstore_wksp );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", args->blockstore_wksp ));
  fd_wksp_tag_query_info_t info;
  ulong tag = 1;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace \"%s\" does not contain a blockstore", args->blockstore_wksp ));
  }
  void * shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, shmem );
  if( ctx->blockstore == NULL ) {
    FD_LOG_ERR(( "failed to join a blockstore" ));
  }
  FD_LOG_NOTICE(( "blockstore has slot root=%lu", ctx->blockstore->shmem->wmk ));
  fd_wksp_mprotect( wksp, 1 );

#define SMAX 1LU<<30
  uchar * smem = aligned_alloc( FD_SPAD_ALIGN, SMAX );
  ctx->spad = fd_spad_join( fd_spad_new( smem, SMAX ) );
  fd_spad_push( ctx->spad );

  ctx->filter = geys_filter_create(ctx->spad, ctx->funk);

  ctx->rep_notify = replay_sham_link_new( aligned_alloc( replay_sham_link_align(), replay_sham_link_footprint() ), args->notify_wksp );

  return ctx;
}

geys_filter_t *
geys_get_filter( geys_fd_ctx_t * ctx ) {
  return ctx->filter;
}

void
geys_fd_loop( geys_fd_ctx_t * ctx ) {
  replay_sham_link_start( ctx->rep_notify );
  while( 1 ) {
    fd_replay_notif_msg_t msg;
    replay_sham_link_poll( ctx->rep_notify, ctx, &msg );
  }
}

static void
replay_sham_link_during_frag(geys_fd_ctx_t * ctx, fd_replay_notif_msg_t * state, void const * msg, int sz) {
  (void)ctx;
  FD_TEST( sz == (int)sizeof(fd_replay_notif_msg_t) );
  fd_memcpy(state, msg, sizeof(fd_replay_notif_msg_t));
}

static void
replay_sham_link_after_frag(geys_fd_ctx_t * ctx, fd_replay_notif_msg_t * msg) {
  fd_spad_push( ctx->spad );
  do {
    if( msg->type == FD_REPLAY_SLOT_TYPE ) {
      if( msg->slot_exec.shred_cnt == 0 ) break;

      FD_SPAD_FRAME_BEGIN( ctx->spad ) {
        ulong blk_max = msg->slot_exec.shred_cnt * FD_SHRED_MAX_SZ;
        uchar * blk_data = fd_spad_alloc( ctx->spad, 1, blk_max );
        ulong blk_sz;
        if( fd_blockstore_slice_query( ctx->blockstore, msg->slot_exec.slot, 0, (uint)(msg->slot_exec.shred_cnt-1), blk_max, blk_data, &blk_sz) ) {
          FD_LOG_WARNING(( "unable to read slot %lu from blockstore", msg->slot_exec.slot ));
          break;
        }

        FD_LOG_NOTICE(( "received slot %lu", msg->slot_exec.slot ));
        geys_filter_notify( ctx->filter, msg, blk_data, blk_sz );
      } FD_SPAD_FRAME_END;
    }
  } while(0);
  fd_spad_pop( ctx->spad );
}

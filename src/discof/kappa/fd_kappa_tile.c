#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topo.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/fd_kappa_tile_seccomp.h"

#include "../../disco/net/fd_net_tile.h"
#include "../../flamenco/types/fd_types.h"

/* This is starting to look pretty similar to the archiver writer/feeder,
   but the end goal of this is to plug into the UI, so its chill . */

#define FD_ARCHIVER_WRITER_ALLOC_TAG   (3UL)
#define FD_ARCHIVER_WRITER_OUT_BUF_SZ  (4096UL)  /* My local filesystem block size */

#define IN_KIND_SHRED  (0UL)
#define IN_KIND_REPAIR (1UL)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_capture_in_ctx_t;

struct fd_capture_tile_ctx {
  uchar               in_kind[ 32 ];
  fd_capture_in_ctx_t in_links[ 32 ];

  int skip_frag;
  ushort repair_intake_listen_port;

  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  ulong repair_buffer_sz;
  uchar repair_buffer[ FD_NET_MTU ];

  fd_ip4_udp_hdrs_t intake_hdr[1];

  ulong now;
  ulong  last_packet_ns;
  double tick_per_ns;

  fd_io_buffered_ostream_t shred_ostream;
  fd_io_buffered_ostream_t repair_ostream;

  int  shreds_fd;
  int  repairs_fd;

  uchar shred_buf[FD_ARCHIVER_WRITER_OUT_BUF_SZ];
  uchar repair_buf[FD_ARCHIVER_WRITER_OUT_BUF_SZ];
};
typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_kappa_tile( out_cnt,
                                             out,
                                             (uint)fd_log_private_logfile_fd(),
                                             (uint)tile->kappa.shreds_fd,
                                             (uint)tile->kappa.requests_fd );
  return sock_filter_policy_fd_kappa_tile_instr_cnt;
}


FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline int
before_frag( fd_capture_tile_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED ) ) {
    FD_LOG_INFO(("kappa SEQ %lu, sig %lu", seq, sig));
    return (fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED) & (fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR);
  }
  return 0;
}


static inline void
during_frag( fd_capture_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq     FD_PARAM_UNUSED,
             ulong                   sig     FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl FD_PARAM_UNUSED ) {
  ctx->skip_frag = 0;
  if( ctx->in_kind[ in_idx ] == IN_KIND_SHRED ) {
    uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in_links[ in_idx ].net_rx, chunk, ctl, sz );
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    fd_shred_t const * shred = fd_shred_parse( dcache_entry+hdr_sz, sz-hdr_sz );
    if( FD_UNLIKELY( !shred ) ) {
      ctx->skip_frag = 1;
      return;
    };
    FD_LOG_INFO(("kappa shred slot %lu, idx %u, is_repair %d, sig %lu", shred->slot, shred->idx, fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR, sig ));
    fd_memcpy( ctx->shred_buffer, dcache_entry+hdr_sz, sz-hdr_sz );
    ctx->shred_buffer_sz = sz-hdr_sz;

  } else if( ctx->in_kind[ in_idx ] == IN_KIND_REPAIR ) {
    ctx->skip_frag = 1;
    return;
    // repair will have outgoing pings, outgoing repair requests, and outgoing served shreds
    // we want to filter everything but the repair requests

    // can index into the ip4 udp packet hdr and check if the src port is the intake listen port or serve port

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );
    fd_ip4_udp_hdrs_t const * hdr = (fd_ip4_udp_hdrs_t const *)dcache_entry;
    if( hdr->udp->net_sport != fd_ushort_bswap( ctx->repair_intake_listen_port ) ) {
      ctx->skip_frag = 1;
      return;
    }
    const uchar * encoded_protocol = dcache_entry + sizeof(fd_ip4_udp_hdrs_t);
    uint discriminant = FD_LOAD(uint, encoded_protocol);

    if( FD_UNLIKELY( discriminant <= fd_repair_protocol_enum_pong ) ) {
      ctx->skip_frag = 1;
      return;
    }
    fd_memcpy( ctx->repair_buffer, encoded_protocol, sz - sizeof(fd_ip4_udp_hdrs_t) );
    ctx->repair_buffer_sz = sz - sizeof(fd_ip4_udp_hdrs_t);
  }
}

static inline void
after_frag( fd_capture_tile_ctx_t * ctx,
            ulong                   in_idx FD_PARAM_UNUSED,
            ulong                   seq    FD_PARAM_UNUSED,
            ulong                   sig    FD_PARAM_UNUSED,
            ulong                   sz,
            ulong                   tsorig FD_PARAM_UNUSED,
            ulong                   tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *     stem   FD_PARAM_UNUSED ) {
  (void)in_idx;
  (void)ctx;
  (void)sz;
  /* Write frag to file */
  //int err = fd_io_buffered_ostream_write( &ctx->shred_ostream, ctx->frag_buf, sz );
  //if( FD_UNLIKELY( err != 0 ) ) {
  //  FD_LOG_WARNING(( "failed to write %lu bytes to output buffer. error: %d", sz, err ));
  //}
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  if( ctx->in_kind[ in_idx ] == IN_KIND_SHRED ) {
    // if leader schedyle not ready it wouldve gotten skipped in shred_tile, but too much work here...

    fd_shred_t const * shred = fd_shred_parse( ctx->shred_buffer, ctx->shred_buffer_sz );
    int   is_turbine = fd_disco_netmux_sig_proto( sig ) == DST_PROTO_SHRED;
    uint  nonce      = is_turbine ? 0 : FD_LOAD(uint, ctx->shred_buffer + fd_shred_sz( shred ) );
    int   is_data    = fd_shred_is_data( fd_shred_type( shred->variant ) );
    ulong slot       = shred->slot;
    uint  idx        = shred->idx;
    FD_LOG_INFO(("kappa kept: slot %lu, idx %u, is_repair %d, sig %lu", shred->slot, shred->idx, fd_disco_netmux_sig_proto( sig )==DST_PROTO_REPAIR, sig ));

    char repair_data_buf[1024];
    snprintf( repair_data_buf, sizeof(repair_data_buf),
             "%ld,%lu,%u,%d,%d,%u\n",
              fd_log_wallclock(), slot, idx, is_turbine, is_data, nonce );

    int err = fd_io_buffered_ostream_write( &ctx->shred_ostream, repair_data_buf, strlen(repair_data_buf) );
    FD_TEST( err==0 );

    //ulong wsz = 0;
    //int err = fd_io_write( ctx->shreds_fd, repair_data_buf, strlen(repair_data_buf), strlen(repair_data_buf), &wsz );
    //FD_TEST( err==0 );
  } else {
    // We have a valid repair request that we can finally decode. unfortunately we actually have to decode because i cant cast directly to the protocol
    // struct, the VERY END gets fucked. but sadly the slot and shred idx are at the end which are importante
    fd_repair_protocol_t protocol;
    fd_bincode_decode_ctx_t bctx = { .data = ctx->repair_buffer, .dataend = ctx->repair_buffer + ctx->repair_buffer_sz };
    fd_repair_protocol_t * decoded = fd_repair_protocol_decode( &protocol, &bctx );

    FD_TEST( decoded == &protocol );
    FD_TEST( decoded != NULL );
    //FD_LOG_NOTICE(( "decoded repair req slot?? %lu", protocol.inner.window_index.slot ));
    uint nonce = protocol.inner.window_index.header.nonce;
    char repair_data_buf[1024];
    snprintf( repair_data_buf, sizeof(repair_data_buf),
              "%ld,%u,%lu,%d\n",
              fd_log_wallclock(), nonce, protocol.inner.window_index.slot, 0 );
    //ulong wsz;
    //int err = fd_io_write( ctx->repairs_fd, repair_data_buf, strlen(repair_data_buf), strlen(repair_data_buf), &wsz );
    //FD_TEST( err==0 );
  }
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)out_fds_cnt;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->kappa.shreds_fd ) )
    out_fds[ out_cnt++ ] = tile->kappa.shreds_fd; /* shred file */
  if( FD_LIKELY( -1!=tile->kappa.requests_fd ) )
    out_fds[ out_cnt++ ] = tile->kappa.requests_fd; /* request file */

  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo;
  char file_path[PATH_MAX];
  strcpy( file_path, tile->kappa.folder_path );
  strcat( file_path, "/shred_data.csv" );
  tile->kappa.shreds_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  FD_LOG_NOTICE(( "Opening shred csv dump file at %s", file_path ));
  if ( FD_UNLIKELY( tile->kappa.shreds_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create shred csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }

  strcpy( file_path, tile->kappa.folder_path );
  strcat( file_path, "/request_data.csv" );
  tile->kappa.requests_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->kappa.requests_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create request csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Setup the csv files to be in the expected state */

  ctx->shreds_fd = tile->kappa.shreds_fd;
  ctx->repairs_fd = tile->kappa.requests_fd;

  int err = ftruncate( ctx->shreds_fd, 0UL );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to truncate the shred file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  long seek = lseek( ctx->shreds_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the shred file" ));
  }

  err = ftruncate( ctx->repairs_fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_ERR(( "failed to truncate the shred file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  seek = lseek( ctx->repairs_fd, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of the shred file" ));
  }

  /* Input links */
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    if( 0==strcmp( link->name, "net_shred" ) ) {
      ctx->in_kind[ i ] = IN_KIND_SHRED;
      fd_net_rx_bounds_init( &ctx->in_links[ i ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "repair_net" ) ) {
      ctx->in_kind[ i ] = IN_KIND_REPAIR;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));
    }

    ctx->in_links[ i ].mem    = link_wksp->wksp;
    ctx->in_links[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ i ].mem, link->dcache );
    ctx->in_links[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ i ].mem, link->dcache, link->mtu );
  }

  ctx->repair_intake_listen_port = tile->kappa.repair_intake_listen_port;

  //fd_ip4_udp_hdr_init( ctx->intake_hdr, FD_REPAIR_MAX_PACKET_SIZE, 0, ctx->repair_intake_listen_port );

  /* Initialize output stream */
  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    &ctx->shred_ostream,
    tile->kappa.shreds_fd,
    ctx->shred_buf,
    FD_ARCHIVER_WRITER_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }
  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    &ctx->repair_ostream,
    tile->kappa.requests_fd,
    ctx->repair_buf,
    FD_ARCHIVER_WRITER_OUT_BUF_SZ ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }

  err = fd_io_buffered_ostream_write( &ctx->shred_ostream, "timestamp,slot,idx,is_turbine,is_data,nonce\n", 44UL );

  //err = fd_io_write( ctx->shreds_fd, "timestamp,slot,idx,is_turbine,is_data,nonce\n", 44UL, 44UL, &sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to write header to shred file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_BEFORE_FRAG          before_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_kappa = {
  .name                     = "kappa",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#include "../../../../disco/tiles.h"

#include "generated/fwd_seccomp.h"

#include "../../../../disco/quic/fd_tpu.h"
#include "../../../../util/net/fd_net_headers.h"

#include <asm-generic/socket.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <unistd.h>
#include <net/if.h>

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_fwd_tile_in_ctx_t;

typedef struct {
  ulong round_robin_idx;
  ulong round_robin_cnt;

  uint   src_ip_addr;
  ushort src_ip_port;
  uchar  src_mac_addr[ 6 ];
  uint   dst_ip_addr;
  ushort dst_ip_port;
  uchar  dst_mac_addr[ 6 ];

  uint  interface_idx;
  int   sock_fd;
  uchar send_buf[ FD_NET_MTU ];

  fd_fwd_tile_in_ctx_t in[ 32 ];
} fd_fwd_tile_ctx_t;

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_fwd_tile_ctx_t ), sizeof( fd_fwd_tile_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
before_frag( fd_fwd_tile_ctx_t * ctx,
             ulong               in_idx,
             ulong               seq,
             ulong               sig ) {
  (void)in_idx;
  (void)sig;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

/* during_frag is called between pairs for sequence number checks, as
   we are reading incoming frags.  We don't actually need to copy the
   fragment here, see fd_dedup.c for why we do this.*/

static inline void
during_frag( fd_fwd_tile_ctx_t * ctx,
             ulong               in_idx,
             ulong               seq,
             ulong               sig,
             ulong               chunk,
             ulong               sz ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  fd_memcpy( ctx->send_buf+sizeof(fd_net_hdrs_t), src, sz );
}

static inline void
after_frag( fd_fwd_tile_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)tsorig;
  (void)stem;

  /* At this point, the payload only contains the serialized txn.
     Beyond end of txn, but within bounds of msg layout, add a trailer
     describing the txn layout.

     [ payload          ] (payload_sz bytes)
     [ pad: align to 2B ] (0-1 bytes)
     [ fd_txn_t         ] (? bytes)
     [ payload_sz       ] (2B) */

  ulong payload_sz = sz;

  fd_net_hdrs_t * hdrs = (fd_net_hdrs_t *)ctx->send_buf;
  hdrs = fd_net_create_packet_header_template( hdrs, payload_sz, ctx->src_ip_addr, ctx->src_mac_addr, (ushort)ctx->src_ip_port );
  memcpy( hdrs->eth->src, ctx->dst_mac_addr, 6UL );
  memcpy( hdrs->ip4->daddr_c, &ctx->dst_ip_addr, 4UL );
  hdrs->udp->net_dport = fd_ushort_bswap( (ushort)ctx->dst_ip_port );
  hdrs->udp->check = fd_ip4_udp_check( *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdrs->ip4->saddr_c ),
                                      *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdrs->ip4->daddr_c ),
                                      (fd_udp_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdrs->udp ),
                                      ctx->send_buf + sizeof(fd_net_hdrs_t) );

  struct sockaddr_ll sock_addr = {
    .sll_family = AF_PACKET,
    .sll_halen = 6,
    .sll_protocol = ETH_P_IP,
    .sll_ifindex = (int)ctx->interface_idx,
  };
  memcpy( sock_addr.sll_addr, ctx->dst_mac_addr, 6UL );
  if( sendto( ctx->sock_fd, ctx->send_buf, sizeof(fd_net_hdrs_t)+payload_sz, 0, (struct sockaddr*)fd_type_pun(&sock_addr), sizeof(struct sockaddr_ll) )<0 ) {
    FD_LOG_WARNING(("sendto: %u-%s", errno, strerror(errno)));
  }
}

static void
privileged_init( FD_PARAM_UNUSED fd_topo_t *      topo,
                 FD_PARAM_UNUSED fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_fwd_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_fwd_tile_ctx_t ), sizeof( fd_fwd_tile_ctx_t ) );

  int sock_fd = socket( AF_PACKET, SOCK_RAW, 0 );
  if( sock_fd<0 ) {
    perror("socket");
  }

  ulong iface_len = strnlen( tile->fwd.interface, 16 );
  FD_TEST( iface_len<16 );

  ctx->interface_idx = if_nametoindex( tile->fwd.interface );
  if( setsockopt( sock_fd, SOL_SOCKET, SO_BINDTODEVICE, tile->fwd.interface, (uint)iface_len )<0 ) {
    perror( "setsockopt" );
  }

  ctx->sock_fd = sock_fd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_fwd_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_fwd_tile_ctx_t ), sizeof( fd_fwd_tile_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->dst_ip_addr = tile->fwd.dst_ip_addr;
  ctx->src_ip_addr = tile->fwd.src_ip_addr;
  ctx->dst_ip_port = tile->fwd.dst_ip_port;
  ctx->src_ip_port = tile->fwd.src_ip_port;

  memcpy( ctx->dst_mac_addr, tile->fwd.dst_mac_addr, sizeof(ctx->dst_mac_addr) );
  memcpy( ctx->src_mac_addr, tile->fwd.src_mac_addr, sizeof(ctx->src_mac_addr) );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( link->is_reasm ) ) {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->reasm_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_laddr_to_chunk( ctx->in[i].mem, link->reasm );
      ctx->in[i].wmark  = ctx->in[i].chunk0 + (link->depth+link->burst-1) * FD_TPU_REASM_CHUNK_MTU;
    } else {
      fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->in[i].mem = link_wksp->wksp;
      ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
      ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    }
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_fwd_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_fwd_tile_ctx_t ), sizeof( fd_fwd_tile_ctx_t ) );

  populate_sock_filter_policy_fwd( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->sock_fd );
  return sock_filter_policy_fwd_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_fwd_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_fwd_tile_ctx_t ), sizeof( fd_fwd_tile_ctx_t ) );
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  out_fds[ out_cnt++ ] = ctx->sock_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_fwd_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_fwd_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_fwd = {
  .name                     = "fwd",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

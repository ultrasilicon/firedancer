#include "fd_snp.h"
#include "fd_snp_private.h"

ulong
fd_snp_footprint( fd_snp_limits_t const * limits ) {
  fd_snp_layout_t layout;
  return fd_snp_footprint_ext( limits, &layout );
}

ulong
fd_snp_footprint_ext( fd_snp_limits_t const * limits,
                      fd_snp_layout_t *       layout ) {
  memset( layout, 0, sizeof(fd_snp_layout_t) );
  if( FD_UNLIKELY( !limits ) ) return 0UL;

  ulong  conn_cnt         = limits->conn_cnt;
  // ulong  conn_id_cnt      = limits->conn_id_cnt;
  // ulong  log_depth        = limits->log_depth;
  // ulong  handshake_cnt    = limits->handshake_cnt;
  // ulong  inflight_pkt_cnt = limits->inflight_pkt_cnt;
  // ulong  tx_buf_sz        = limits->tx_buf_sz;
  // ulong  stream_pool_cnt  = limits->stream_pool_cnt;

  if( FD_UNLIKELY( conn_cnt        ==0UL ) ) { FD_LOG_WARNING(( "invalid conn_cnt==0" )); return 0UL; }

  layout->meta_sz = sizeof(fd_snp_layout_t);

  /* allocate space for fd_snp_t */
  ulong offs = sizeof(fd_snp_t);

  /* allocate space for connections */
  offs                      = fd_ulong_align_up( offs, fd_snp_conn_pool_align() );
  layout->conn_pool_off     = offs;
  ulong conn_pool_footprint = fd_snp_conn_pool_footprint( limits->conn_cnt );
  if( FD_UNLIKELY( !conn_pool_footprint ) ) { FD_LOG_WARNING(( "invalid fd_snp_conn_pool_footprint" )); return 0UL; }
  offs                     += conn_pool_footprint;

  /* allocate space for conn IDs */
  offs                      = fd_ulong_align_up( offs, fd_snp_conn_map_align() );
  layout->conn_map_off      = offs;
  ulong conn_map_footprint  = fd_snp_conn_map_footprint( 1 + fd_ulong_find_msb( limits->conn_cnt ) );
  if( FD_UNLIKELY( !conn_map_footprint ) ) { FD_LOG_WARNING(( "invalid fd_snp_conn_map_footprint" )); return 0UL; }
  offs                     += conn_map_footprint;

  /* allocate space for packets */
  offs                      = fd_ulong_align_up( offs, fd_snp_pkt_pool_align() );
  layout->pkt_pool_off      = offs;
  ulong pkt_pool_footprint  = fd_snp_pkt_pool_footprint( limits->conn_cnt ); //FIXME
  if( FD_UNLIKELY( !pkt_pool_footprint ) ) { FD_LOG_WARNING(( "invalid fd_snp_pkt_pool_footprint (pkt_pool)" )); return 0UL; }
  offs                     += pkt_pool_footprint;

  /* allocate space for connections' last packet */
  offs                      = fd_ulong_align_up( offs, fd_snp_pkt_pool_align() );
  layout->last_pkt_pool_off = offs;
  ulong last_pkt_footprint  = fd_snp_pkt_pool_footprint( limits->conn_cnt );
  if( FD_UNLIKELY( !last_pkt_footprint ) ) { FD_LOG_WARNING(( "invalid fd_snp_pkt_pool_footprint (last_pkt_pool)" )); return 0UL; }
  offs                     += last_pkt_footprint;

  return offs;
}

ulong
fd_snp_clock_wallclock( void * ctx FD_PARAM_UNUSED ) {
  return (ulong)fd_log_wallclock();
}

void *
fd_snp_new( void* mem,
            fd_snp_limits_t const * limits ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong align = fd_snp_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !limits ) ) {
    FD_LOG_WARNING(( "NULL limits" ));
    return NULL;
  }

  if( FD_UNLIKELY( limits->conn_cnt == 0UL ) ) {
    FD_LOG_WARNING(( "invalid limits" ));
    return NULL;
  }

  fd_snp_layout_t layout;
  ulong footprint = fd_snp_footprint_ext( limits, &layout );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  /* Zero the entire memory region */
  fd_snp_t * snp = (fd_snp_t *)mem;
  memset( snp, 0, fd_snp_footprint( limits ) );

  /* Store the limits */
  snp->limits = *limits;
  snp->layout = layout;

  /* Initialize private data */
  // fd_snp_state_private_t* priv = snp->priv;

  /* Initialize session arrays */
  // priv->session_sz = 0;
  // priv->client_hs_sz = 0;
  // priv->server_hs_sz = 0;
  // fd_rng_join( fd_rng_new( priv->_rng, 32, 44 ) );

  /* Set magic number to indicate successful initialization */
  FD_COMPILER_MFENCE();
  snp->magic = FD_SNP_MAGIC;
  FD_COMPILER_MFENCE();

  return snp;
}

fd_snp_t *
fd_snp_join( void* shsnp ) {
  //FIXME
  return shsnp;
}

fd_snp_t *
fd_snp_init( fd_snp_t * snp ) {

  fd_snp_limits_t const * limits = &snp->limits;
  fd_snp_config_t       * config = &snp->config;

  (void)config;
  // if( FD_UNLIKELY( config->tick_per_us==0 ) ) { FD_LOG_WARNING(( "zero cfg.tick_per_us"  )); return NULL; }


  /* Validate layout */
  fd_snp_layout_t layout = {0};
  if( FD_UNLIKELY( !fd_snp_footprint_ext( limits, &layout ) ) ) {
    FD_LOG_WARNING(( "fd_snp_footprint_ext failed" ));
  }
  if( FD_UNLIKELY( 0!=memcmp( &layout, &snp->layout, sizeof(fd_snp_layout_t) ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "saved layout",   &snp->layout, sizeof(fd_snp_layout_t) ));
    FD_LOG_HEXDUMP_WARNING(( "derived layout", &layout,      sizeof(fd_snp_layout_t) ));
    FD_LOG_WARNING(( "fd_snp_layout changed. Memory corruption?" ));
  }

  /* Initialize apps (statically allocated) */
  if( FD_UNLIKELY( snp->apps_cnt > sizeof(snp->apps)/sizeof(fd_snp_applications_t) ) ) {
    FD_LOG_WARNING(( "[snp] invalid apps_cnt=%lu", snp->apps_cnt ));
    return NULL;
  }
  for( ulong j=0; j<snp->apps_cnt; j++ ) {
    if( FD_UNLIKELY( snp->apps[j].port==0 ) ) {
      FD_LOG_WARNING(( "[snp] invalid apps[%lu].port=%hu", j, snp->apps[j].port ));
      return NULL;
    }
    fd_ip4_udp_hdr_init( snp->apps[j].net_hdr, 0, 0, snp->apps[j].port );
  }

  /* Initialize conn_pool */
  uchar * conn_pool_laddr = (uchar *)snp + layout.conn_pool_off;
  snp->conn_pool = fd_snp_conn_pool_join( fd_snp_conn_pool_new( conn_pool_laddr, limits->conn_cnt ) );
  if( FD_UNLIKELY( !snp->conn_pool ) ) {
    FD_LOG_WARNING(( "NULL conn_pool" ));
    return NULL;
  }

  /* Initialize conn_map */
  uchar * conn_map_laddr = (uchar *)snp + layout.conn_map_off;
  snp->conn_map = fd_snp_conn_map_join( fd_snp_conn_map_new( (void *)conn_map_laddr, 1 + fd_ulong_find_msb( limits->conn_cnt ) ) );
  if( FD_UNLIKELY( !snp->conn_map ) ) {
    FD_LOG_WARNING(( "NULL conn_map" ));
    return NULL;
  }

  /* Initialize pkt_pool */
  uchar * pkt_pool_laddr = (uchar *)snp + layout.pkt_pool_off;
  snp->pkt_pool = fd_snp_pkt_pool_join( fd_snp_pkt_pool_new( pkt_pool_laddr, limits->conn_cnt ) ); //FIXME: limits->conn_cnt
  if( FD_UNLIKELY( !snp->pkt_pool ) ) {
    FD_LOG_WARNING(( "NULL pkt_pool" ));
    return NULL;
  }

  /* Initialize last_pkt_pool */
  uchar * last_pkt_pool_laddr = (uchar *)snp + layout.last_pkt_pool_off;
  snp->last_pkt_pool = fd_snp_pkt_pool_join( fd_snp_pkt_pool_new( last_pkt_pool_laddr, limits->conn_cnt ) );
  if( FD_UNLIKELY( !snp->last_pkt_pool ) ) {
    FD_LOG_WARNING(( "NULL last_pkt_pool" ));
    return NULL;
  }

  /* Initialize private state */
  fd_rng_join( fd_rng_new( snp->config._rng, (uint)fd_tickcount(), 0UL ) );
  uchar random_aes_key[ 16 ] = { 0 };
  fd_snp_rng( random_aes_key, 16 );
  fd_aes_set_encrypt_key( random_aes_key, 128, snp->config._state_enc_key );
  fd_aes_set_decrypt_key( random_aes_key, 128, snp->config._state_dec_key );

  return snp;
}

fd_snp_t *
fd_snp_fini( fd_snp_t* snp ) {
  return snp;
}

/* Connections */

#define FD_SNP_MAX_SESSION_ID_RETRIES (10)

/* fd_snp_conn_create a new fd_snp_conn_t struct from the snp pool,
   and inserts in the snp map by peer_addr and by session_id. */
static inline fd_snp_conn_t *
fd_snp_conn_create( fd_snp_t * snp,
                    ulong      peer_addr,
                    uchar      is_server ) {
  fd_snp_conn_map_t * entry = NULL;
  ulong session_id = 0UL;
  int i = 0;

  /* get a new conn from pool */
  fd_snp_conn_t * conn = fd_snp_conn_pool_ele_acquire( snp->conn_pool );
  if( FD_UNLIKELY( conn==NULL ) ) {
    /* fd_snp_conn_pool_ele_acquire failed */
    return NULL; /* nothing was acquired */
  }

  /* get a new last_pkt from pool */
  fd_snp_pkt_t * last_pkt = fd_snp_pkt_pool_ele_acquire( snp->last_pkt_pool );
  if( FD_UNLIKELY( last_pkt==NULL ) ) {
    /* fd_snp_pkt_pool_ele_acquire failed */
    goto err;
  }

  /* insert conn in map by session_id. do NOT ignore failure.
     session_id is randomly generated, in case of failure we
     retry FD_SNP_MAX_SESSION_ID_RETRIES times, then fail. */
  for( i=0, entry=NULL; i<FD_SNP_MAX_SESSION_ID_RETRIES && entry==NULL; i++ ) {
    session_id = fd_rng_ulong( snp->config._rng );
    entry = fd_snp_conn_map_insert( snp->conn_map, session_id );
  }
  if( FD_LIKELY( entry ) ) {
    entry->val = conn;
  } else {
    /* fd_snp_conn_map_insert(..., sessio_id) failed n times */
    goto err;
  }

  /* insert conn in map by peer_addr. ignore failure.
     if this fails, there's already a conn for peer_addr. */
  entry = fd_snp_conn_map_insert( snp->conn_map, peer_addr );
  if( FD_LIKELY( entry ) ) {
    entry->val = conn;
  }

  /* init conn */
  conn->peer_addr = peer_addr;
  conn->session_id = session_id;
  conn->state = FD_SNP_STATE_INVALID;
  conn->last_pkt = last_pkt;
  conn->_pubkey = snp->config.identity;
  conn->is_server = is_server;

  /* init last_pkt */
  last_pkt->data_sz = 0;

  return conn;

err:
  if( last_pkt ) {
    fd_snp_pkt_pool_ele_release( snp->last_pkt_pool, last_pkt );
  }
  if( conn ) {
    fd_snp_conn_pool_ele_release( snp->conn_pool, conn );
  }
  return NULL;
}

static inline int
fd_snp_conn_delete( fd_snp_t * snp,
                    fd_snp_conn_t * conn ) {
  fd_snp_pkt_pool_ele_release( snp->last_pkt_pool, conn->last_pkt );

  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry0 = fd_snp_conn_map_query( snp->conn_map, conn->peer_addr, &sentinel );
  if( entry0->val && entry0->val->session_id==conn->session_id ) {
    fd_snp_conn_map_remove( snp->conn_map, entry0 );
  }
  fd_snp_conn_map_t * entry1 = fd_snp_conn_map_query( snp->conn_map, conn->session_id, &sentinel );
  if( entry1->val ) {
    fd_snp_conn_map_remove( snp->conn_map, entry1 );
  }

  conn->session_id = 0UL;
  fd_snp_conn_pool_ele_release( snp->conn_pool, conn );
  return 0;
}

static inline fd_snp_conn_t *
fd_snp_conn_query( fd_snp_t * snp,
                   ulong      session_id ) {
  if( FD_UNLIKELY( !session_id ) ) {
    return NULL;
  }
  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, session_id, &sentinel );
  return entry->val;
}

static inline fd_snp_conn_t *
fd_snp_conn_query_by_peer( fd_snp_t * snp,
                           ulong      peer_addr ) {
  if( FD_UNLIKELY( !peer_addr ) ) {
    return NULL;
  }
  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, peer_addr, &sentinel );
  return entry->val;
}

static inline int
fd_snp_finalize_udp_and_invoke_tx_cb(
  fd_snp_t *    snp,
  uchar *       packet,
  ulong         packet_sz,
  fd_snp_meta_t meta
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }

  uchar snp_app_id;
  ushort dst_port;
  uint dst_ip;
  fd_snp_meta_into_parts( NULL, &snp_app_id, &dst_ip, &dst_port, meta );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( snp->apps[ snp_app_id ].net_hdr );
  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dst_ip;
  ip4->net_id = fd_ushort_bswap( snp->apps[ snp_app_id ].net_id++ );
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );
  hdr->udp->net_dport  = fd_ushort_bswap( dst_port );
  hdr->udp->net_len    = fd_ushort_bswap( (ushort)( packet_sz - sizeof(fd_ip4_udp_hdrs_t) + sizeof(fd_udp_hdr_t) ) );

  // FD_LOG_NOTICE(( "fd_snp_finalize_udp_and_invoke_tx_cb meta=%016lx", meta ));
  return snp->cb.tx ? snp->cb.tx( snp->cb.ctx, packet, packet_sz, meta ) : (int)packet_sz;
}

static inline int
fd_snp_finalize_snp_and_invoke_tx_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }
  fd_snp_v1_finalize_packet( conn, packet+sizeof(fd_ip4_udp_hdrs_t), packet_sz-sizeof(fd_ip4_udp_hdrs_t) );
  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta & (~FD_SNP_META_OPT_HANDSHAKE) );
}

static inline int
fd_snp_verify_snp_and_invoke_rx_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta
) {
  int res = fd_snp_v1_validate_packet( conn, packet+sizeof(fd_ip4_udp_hdrs_t), packet_sz-sizeof(fd_ip4_udp_hdrs_t) );
  if( FD_UNLIKELY( res < 0 ) ) {
    return -1;
  }
  return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
}

static inline int
fd_snp_cache_packet_and_invoke_sign_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  int             packet_snp_sz, /* without headers */
  uchar *         to_sign
) {
  if( FD_LIKELY( packet_snp_sz > 0 ) ) {
    conn->last_sent_ts = fd_snp_timestamp_ms();
    conn->retry_cnt = 0;
    conn->last_pkt->data_sz = (ushort)((ulong)packet_snp_sz+sizeof(fd_ip4_udp_hdrs_t));
    memcpy( conn->last_pkt->data, packet, conn->last_pkt->data_sz );
    return snp->cb.sign( snp->cb.ctx, conn->session_id, to_sign );
  }
  return packet_snp_sz;
}

int
fd_snp_cache_packet_for_retry( fd_snp_conn_t * conn,
                               uchar const *   packet,
                               ulong           packet_sz,
                               fd_snp_meta_t   meta ) {
  if( conn==NULL ) {
    return -1;
  }
  conn->last_sent_ts = fd_snp_timestamp_ms();
  conn->retry_cnt = 0;
  memcpy( conn->last_pkt->data, packet, packet_sz );
  conn->last_pkt->data_sz = (ushort)packet_sz;
  conn->last_pkt->meta = meta;
  return 0;
}

int
fd_snp_retry_cached_packet( fd_snp_t *      snp,
                            fd_snp_conn_t * conn ) {
  uchar * packet = conn->last_pkt->data;
  ulong   packet_sz = conn->last_pkt->data_sz;
  fd_snp_meta_t meta = conn->last_pkt->meta;
  conn->last_sent_ts = fd_snp_timestamp_ms();
  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_BUFFERED );
}

static inline void
fd_snp_pkt_pool_store( fd_snp_t *            snp,
                       fd_snp_conn_t const * conn,
                       uchar const *         packet,
                       ulong                 packet_sz,
                       uchar                 send ) {
  fd_snp_pkt_t * pkt = fd_snp_pkt_pool_ele_acquire( snp->pkt_pool );
  if( FD_LIKELY( pkt ) ) {
    pkt->session_id = conn->session_id;
    memcpy( pkt->data, packet, packet_sz );
    pkt->data_sz = (ushort)packet_sz;
    pkt->send = send;
  }
}

static inline void
fd_snp_pkt_pool_process(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  fd_snp_meta_t   meta
) {
  ulong meta_buffered = ( meta | FD_SNP_META_OPT_BUFFERED );
  ulong max  = fd_snp_pkt_pool_max( snp->pkt_pool );
  ulong used = fd_snp_pkt_pool_used( snp->pkt_pool );
  ulong idx = 0;
  ulong used_ele = 0;
  fd_snp_pkt_t * ele = snp->pkt_pool;
  for( ; idx<max; idx++, ele++ ) {
    if( ele->session_id == 0 ) continue;
    if( ele->session_id == conn->session_id ) {
      uchar * buf    = ele->data;
      ulong   buf_sz = (ulong)ele->data_sz;

      /* ignore return from callbacks for cached packets */
      if( ele->send==1 ) {
        fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, buf, buf_sz, meta_buffered );
      } else {
        fd_snp_verify_snp_and_invoke_rx_cb( snp, conn, buf, buf_sz, meta_buffered );
      }

      /* delete cached packet */
      ele->session_id = 0;
      fd_snp_pkt_pool_idx_release( snp->pkt_pool, idx );
    }
    if( ++used_ele>=used ) break;
  }
}

/* fd_snp_send sends a packet to a peer.

   Workflow:
   1. Validate input
   2. If proto==UDP, send packet as UDP
   3. Query connection by peer (meta)
   4. (likely case) If we have an established connection, send packet and return
   5. If we don't have a connection, create a new connection
   6. If packet_sz > 0, cache current packet
   7. If we did have a connection, return
   8. Prepare client_initial, overwrite packet
   9. Send client_initial */
int
fd_snp_send( fd_snp_t *    snp,
             uchar *       packet,
             ulong         packet_sz,
             fd_snp_meta_t meta ) {

  /* 1. Validate input */
  if( packet_sz > SNP_BASIC_PAYLOAD_MTU ) {
    return -1;
  }

  /* 2. If proto==UDP, send packet as UDP */
  ulong proto = meta & FD_SNP_META_PROTO_MASK;
  if( FD_LIKELY( proto==FD_SNP_META_PROTO_UDP ) ) {
    FD_LOG_INFO(( "[SNP] UDP send" ));
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta );
  }

  /* 3. Query connection by peer (meta) */
  ulong peer_addr = meta & FD_SNP_META_PEER_MASK;
  FD_LOG_NOTICE(( "fd_snp_conn_query_by_peer peer_addr=%016lx", peer_addr ));
  fd_snp_conn_t * conn = fd_snp_conn_query_by_peer( snp, peer_addr );

  /* 4. (likely case) If we have an established connection, send packet and return */
  if( FD_LIKELY( conn!=NULL && conn->state==FD_SNP_TYPE_HS_DONE ) ) {
    FD_LOG_INFO(( "[SNP] SNP send" ));
    return fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, packet, packet_sz, meta );
  } /* else is implicit */

  /* 5. If we don't have a connection, create a new connection */
  if( conn==NULL ) {
    FD_LOG_NOTICE(( "client fd_snp_conn_create peer_addr=%016lx", peer_addr ));
    conn = fd_snp_conn_create( snp, peer_addr, /* is_server */ 0 );
    if( conn==NULL ) {
      return -1;
    }
    conn->is_server = 0;
  }
  if( FD_UNLIKELY( conn==NULL ) ) {
    FD_LOG_WARNING(( "[SNP] fd_snp_conn_create returned NULL" ));
    return -1;
  }

  /* 6. If packet_sz > 0, cache current packet */
  if( packet_sz>0 ) {
    FD_LOG_INFO(( "[SNP] cache packet" ));
    fd_snp_pkt_pool_store( snp, conn, packet, packet_sz, /* send */ 1 );
  }

  /* 7. If we did have a connection, return */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return 0; /* success */
  } /* else is implicit */

  /* 8. Prepare client_initial, overwrite packet */
  int sz = fd_snp_v1_client_init( &snp->config, conn, NULL, 0UL, packet + sizeof(fd_ip4_udp_hdrs_t), NULL );
  if( FD_UNLIKELY( sz<=0 ) ) {
    FD_LOG_WARNING(( "[SNP] fd_snp_s0_client_initial failed" ));
    return -1;
  }

  /* 9. Send client_initial */
  FD_LOG_INFO(( "[SNP] SNP send hs1 session_id=%016lx", conn->session_id ));
  packet_sz = (ulong)sz + sizeof(fd_ip4_udp_hdrs_t);
  fd_snp_cache_packet_for_retry( conn, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
}

/* Workflow:
   1. Parse UDP: derive which app to send the packet to
   2. Parse SNP: derive proto and meta
   3. If proto==UDP, recv packet as UDP
   4. Query connection by session_id

   5. (likely case) Recv state machine

      R1. If multicast, accept (TODO)
      R2. Validate conn, or drop
      R3. (likely case) conn established + validate integrity, accept
      R4. state==4, cache packet

   6. Handshake state machine
      ...

   7. Send handshake packet (if any)
   8. If connection is established, send/recv cached packets */
int
fd_snp_process_packet( fd_snp_t * snp,
                       uchar *    packet,
                       ulong      packet_sz ) {
  /* 1. Parse UDP: derive which app to send the packet to */
  if( packet_sz <= sizeof(fd_ip4_udp_hdrs_t) ) {
    return -1;
  }

  // int res = fd_snp_parse( &proto, &type, &session_id, &meta, packet, packet_sz );
  // if( FD_UNLIKELY( res < 0 ) ) {
  //   return -1;
  // }

  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  uint src_ip = hdr->ip4->saddr;
  ushort src_port = fd_ushort_bswap( hdr->udp->net_sport );
  ushort dst_port = fd_ushort_bswap( hdr->udp->net_dport );

  uchar snp_app_id;
  for( snp_app_id=0U; snp_app_id<snp->apps_cnt; snp_app_id++ ) {
    if( snp->apps[ snp_app_id ].port == dst_port ) {
      break;
    }
  }
  if( FD_UNLIKELY( snp_app_id>=snp->apps_cnt ) ) {
    /* The packet is not for SNP, ignore */
    FD_LOG_WARNING(( "[SNP] app not found for dst_port=%u", dst_port ));
    return -1;
  }

  /* 2. Parse SNP: derive proto and meta */
  ulong proto = FD_SNP_META_PROTO_UDP;

  //TODO: proper fd_snp_parse()
  if( FD_LIKELY( packet_sz >= sizeof(fd_ip4_udp_hdrs_t) + 4 ) ) {
    uchar const * magic = packet + sizeof(fd_ip4_udp_hdrs_t);
    if( (*magic)=='S' && (*(magic+1))=='O' && (*(magic+2))=='L' ) {
      proto = FD_SNP_META_PROTO_V1;
    }
  }

  fd_snp_meta_t meta = fd_snp_meta_from_parts( proto, snp_app_id, src_ip, src_port );
  ulong peer_addr = meta & FD_SNP_META_PEER_MASK;

  /* 3. If proto==UDP, recv packet as UDP */
  if( proto==FD_SNP_META_PROTO_UDP ) {
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
  } /* else is implicit */

  /* 4. Query connection by session_id */
  snp_hdr_t * head = (snp_hdr_t *)(packet + sizeof(fd_ip4_udp_hdrs_t));
  ulong session_id = head->session_id;
  fd_snp_conn_t * conn = fd_snp_conn_query( snp, session_id );

  /* 5. (likely case) Recv state machine */
  int type = snp_hdr_type( head );
  if( FD_LIKELY( type==FD_SNP_TYPE_PAYLOAD ) ) {
    /* R1. If multicast, accept (TODO) */

    /* R2. Validate conn, or drop */
    if(FD_UNLIKELY( conn==NULL || conn->peer_addr != peer_addr ) ) {
      return -1;
    }

    /* R3. (likely case) conn established + validate integrity, accept */
    if( FD_LIKELY( conn->state==FD_SNP_TYPE_HS_DONE ) ) {
      return fd_snp_verify_snp_and_invoke_rx_cb( snp, conn, packet, packet_sz, meta );
    }

    /* R4. state==4 or 5, cache packet */
    if( FD_LIKELY( conn->state==FD_SNP_TYPE_HS_SERVER_FINI || conn->state==FD_SNP_TYPE_HS_CLIENT_FINI ) ) {
      FD_LOG_INFO(( "caching packet packet_sz=%lu", packet_sz ));
      fd_snp_pkt_pool_store( snp, conn, packet, packet_sz, /* recv */ 0 );
      return 0;
    }

    return -1;
  }

  /* 6. Handshake state machine */

  uchar * pkt = packet + sizeof(fd_ip4_udp_hdrs_t);
  ulong pkt_sz = packet_sz - sizeof(fd_ip4_udp_hdrs_t);
  uchar to_sign[32];
  int sz = 0;
  switch( type ) {

    /* HS1. Server receives client_init and sends server_init */
    case FD_SNP_TYPE_HS_CLIENT_INIT: {
      //TODO: handle both peers sending client_init
      fd_snp_conn_t _conn[1] = { 0 }; _conn->peer_addr = peer_addr;
      sz = fd_snp_v1_server_init( &snp->config, _conn, pkt, pkt_sz, pkt, NULL );
    } break;

    /* HS2. Client receives server_init and sends client_cont */
    case FD_SNP_TYPE_HS_SERVER_INIT: {
      sz = fd_snp_v1_client_cont( &snp->config, conn, pkt, pkt_sz, pkt, NULL );
    } break;

    /* HS3. Server receives client_cont and sends server_fini */
    case FD_SNP_TYPE_HS_CLIENT_CONT: {
      fd_snp_conn_t _conn[1] = { 0 }; _conn->peer_addr = peer_addr;
      sz = fd_snp_v1_server_fini_precheck( &snp->config, _conn, pkt, pkt_sz, pkt, to_sign );
      if( FD_UNLIKELY( sz < 0 ) ) {
        return -1;
      }
      conn = fd_snp_conn_query_by_peer( snp, peer_addr );
      /* The likely case is that conn==NULL, ie. there's no existing conn to the peer,
         and the handshake proceeds as expected. */
      if( FD_LIKELY( conn==NULL || conn->state==FD_SNP_TYPE_HS_DONE ) ) {
        conn = fd_snp_conn_create( snp, peer_addr, /* is_server */ 1 );
        FD_LOG_NOTICE(( "server fd_snp_conn_create peer_addr=%016lx session_id=%016lx", peer_addr, conn->session_id ));
      }
      if( conn==NULL ) {
        return -1;
      }
      if( conn->state==FD_SNP_TYPE_HS_SERVER_FINI ) {
        FD_LOG_NOTICE(( "server retry immediately" ));
        /* This immediate retry is not necessary, but it accelerates the handshake. */
        return fd_snp_retry_cached_packet( snp, conn );
      }
      sz = fd_snp_v1_server_fini( &snp->config, conn, pkt, pkt_sz, pkt, to_sign );
      if( FD_UNLIKELY( sz < 0 ) ) {
        return -1;
      }
      return fd_snp_cache_packet_and_invoke_sign_cb( snp, conn, packet, sz, to_sign );
    } break;

    /* HS4. Client receives server_fini and sends client_fini */
    case FD_SNP_TYPE_HS_SERVER_FINI: {
      FD_LOG_NOTICE(( "client recv SF. state=%u", conn->state ));
      if( FD_LIKELY( conn->state == FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
        sz = fd_snp_v1_client_fini( &snp->config, conn, pkt, pkt_sz, pkt, to_sign );
        return fd_snp_cache_packet_and_invoke_sign_cb( snp, conn, packet, sz, to_sign );
      } else if( conn->state==FD_SNP_TYPE_HS_DONE ) {
        /* This immediate retry is necessary, because from the client perspective
           the handshake is completeled, and thus housekeeping wouldn't be retrying.
           But if the server re-sends server_fini, it means it didn't receive
           client_fini, and so we have to retry. */
        FD_LOG_NOTICE(( "client retry immediately" ));
        return fd_snp_retry_cached_packet( snp, conn );
      }
    } break;

    /* HS5. Server receives client_fini and accepts */
    case FD_SNP_TYPE_HS_CLIENT_FINI: {
      sz = fd_snp_v1_server_acpt( &snp->config, conn, pkt, pkt_sz, pkt, NULL );
      if( FD_LIKELY( sz>=0 ) ) {
        /* Update the default connection to peer_addr to this conn */
        fd_snp_conn_map_t sentinel = { 0 };
        fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, peer_addr, &sentinel );
        if( entry->val!=NULL && entry->val!=conn ) {
          entry->val = conn;
        }
      }
    } break;

    /* Drop any other packet */
    default:
      return -1;
  }

  /* 7. Send handshake packet (if any) */
  if( FD_UNLIKELY( sz < 0 ) ) {
    FD_LOG_WARNING(("SNP handle handshake packet failed"));
    return -1;
  }
  if( FD_LIKELY( sz > 0 ) ) {
    FD_LOG_INFO(( "[SNP] send (unbuffered)" ));
    packet_sz = (ulong)sz + sizeof(fd_ip4_udp_hdrs_t);
    fd_snp_cache_packet_for_retry( conn, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
    sz = fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
  }

  /* 8. If connection is established, send/recv cached packets */
  if( FD_UNLIKELY( conn && conn->state==FD_SNP_TYPE_HS_DONE ) ) {
    fd_snp_pkt_pool_process( snp, conn, meta );
  }

  return sz; /* return value is from the handshake msg, not cached packets */
}

int
fd_snp_process_signature( fd_snp_t *  snp,
                          ulong       session_id,
                          uchar const signature[ 64 ] ) {

  fd_snp_conn_t * conn = fd_snp_conn_query( snp, session_id );
  if( conn==NULL ) {
    return -1;
  }

  fd_snp_meta_t meta = conn->peer_addr | FD_SNP_META_PROTO_V1 | FD_SNP_META_OPT_BUFFERED | FD_SNP_META_OPT_HANDSHAKE;

  int sz;
  switch( conn->state ) {
    /* HS3. Server receives client_cont and sends server_fini */
    case FD_SNP_TYPE_HS_SERVER_FINI_SIG: {
      fd_snp_v1_server_fini_add_signature( conn, conn->last_pkt->data+sizeof(fd_ip4_udp_hdrs_t), signature );
      conn->last_sent_ts = fd_snp_timestamp_ms();
      conn->retry_cnt = 0;
      conn->last_pkt->meta = meta;
      FD_LOG_NOTICE(( "fd_snp_v1_server_fini_add_signature session_id=%016lx", conn->session_id ));
      return fd_snp_finalize_udp_and_invoke_tx_cb( snp, conn->last_pkt->data, conn->last_pkt->data_sz, meta );
    } break;

    /* HS4. Client receives server_fini and sends client_fini */
    case FD_SNP_TYPE_HS_CLIENT_FINI_SIG: {
      fd_snp_v1_client_fini_add_signature( conn, conn->last_pkt->data+sizeof(fd_ip4_udp_hdrs_t), signature );
      sz = fd_snp_finalize_udp_and_invoke_tx_cb( snp, conn->last_pkt->data, conn->last_pkt->data_sz, meta );

      /* process cached packets before return */
      fd_snp_pkt_pool_process( snp, conn, meta );

      return sz; /* return value is from the handshake msg, not cached packets */
    } break;
  }
  return -1;
}

int
fd_snp_housekeeping( fd_snp_t * snp ) {
  ulong max  = fd_snp_conn_pool_max( snp->conn_pool );
  ulong used = fd_snp_conn_pool_used( snp->conn_pool );
  ulong idx = 0;
  ulong used_ele = 0;
  fd_snp_conn_t * conn = snp->conn_pool;

#define FD_SNP_HANDSHAKE_RETRY_MAX (10U)
#define FD_SNP_HANDSHAKE_RETRY_MS  (500L)

  long now = fd_snp_timestamp_ms();
  for( ; idx<max; idx++, conn++ ) {
    if( conn->session_id == 0 ) continue;
    if( FD_SNP_STATE_INVALID < conn->state && conn->state < FD_SNP_TYPE_HS_DONE ) {
      if( now > conn->last_sent_ts + FD_SNP_HANDSHAKE_RETRY_MS
        && ++conn->retry_cnt < FD_SNP_HANDSHAKE_RETRY_MAX ) {
        FD_LOG_NOTICE(( "retry %d session_id=%016lx", conn->retry_cnt, conn->session_id ));
        fd_snp_retry_cached_packet( snp, conn );
      }
      if( conn->retry_cnt == FD_SNP_HANDSHAKE_RETRY_MAX ) {
        FD_LOG_NOTICE(( "retry expired - deleting session_id=%016lx", conn->session_id ));
        fd_snp_conn_delete( snp, conn );
      }
    }
    if( ++used_ele>=used ) break;
  }

  return (int)used;
}

#define _POSIX_C_SOURCE 199309L

#include "fd_snp_app.h"
#include "fd_snp_private.h"
#include "fd_snp.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static
void external_generate_keypair( uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  FD_TEST( fd_rng_secure( private_key, 32 )!=NULL );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );
}

struct test_cb_ctx {
  uchar * out_packet;
  uchar * assert_packet;
  ulong   assert_packet_sz;
  uchar * assert_data;
  ulong   assert_data_sz;
  ulong   assert_peer;
  ulong   assert_meta;

  /* buffering */
  uchar   assert_buffered;
  fd_snp_pkt_t buf_packet[2];
  ulong   buf_cnt;

  /* signature */
  ulong   sign_cnt;
  uchar   signature   [ 64 ];
  uchar   public_key  [ 32 ];
  uchar   private_key [ 32 ];
  fd_snp_t * snp; // to invoke fd_snp_process_signature
};
typedef struct test_cb_ctx test_cb_ctx_t;

static int
test_cb_snp_tx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  if( meta & FD_SNP_META_OPT_BUFFERED ) {
    memcpy( ctx->buf_packet[ ctx->buf_cnt ].data, packet, packet_sz );
    ctx->buf_packet[ ctx->buf_cnt ].data_sz = (ushort)packet_sz;
    ctx->buf_cnt++;
  }
  // FD_LOG_HEXDUMP_WARNING(( "packet", packet, packet_sz ));
  return (int)packet_sz;
}

static int
test_cb_snp_rx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  uchar buffered = (meta & FD_SNP_META_OPT_BUFFERED)==FD_SNP_META_OPT_BUFFERED;
  FD_TEST( buffered  == ctx->assert_buffered );
  // FD_LOG_WARNING(( "packet_sz=%lu assert=%lu", packet_sz, ctx->assert_packet_sz ));
  FD_TEST( packet_sz == ctx->assert_packet_sz );
  // FD_LOG_WARNING(( "meta=%016lx assert=%016lx", meta, ctx->assert_meta ));
  FD_TEST( meta      == ctx->assert_meta );
  if( buffered ) {
    ctx->buf_cnt++;
    FD_TEST( fd_memeq( packet, ctx->assert_packet, packet_sz ) );
  } else {
    FD_TEST( packet  == ctx->assert_packet );
  }
  return 1;
}

static int
test_cb_snp_sign( void const *  _ctx,
                  ulong         session_id,
                  uchar const   to_sign[ FD_SNP_TO_SIGN_SZ ] ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  fd_sha512_t sha512[1];
  fd_ed25519_sign( ctx->signature, to_sign, 32, ctx->public_key, ctx->private_key, sha512 );
  ctx->sign_cnt++;
  return fd_snp_process_signature( ctx->snp, session_id, ctx->signature );
}

int
test_cb_app_rx( void const *  _ctx,
                fd_snp_peer_t peer,
                uchar const * data,
                ulong         data_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  FD_TEST( peer    == ctx->assert_peer );
  // FD_LOG_WARNING(( "data_sz=%lu assert=%lu", data_sz, ctx->assert_data_sz ));
  FD_TEST( data_sz == ctx->assert_data_sz );
  FD_TEST( meta    == ctx->assert_meta );
  if( ctx->assert_data ) FD_TEST( fd_memeq( data, ctx->assert_data, data_sz ) );
  return 1;
}

static void
test_snp_app_send_recv_udp( fd_wksp_t * wksp ) {
  ulong proto = FD_SNP_META_PROTO_UDP;
  fd_snp_limits_t limits = { .conn_cnt = 256 };

  /* Client */
  ushort client_port = 1234;
  test_cb_ctx_t client_cb_test[1] = { 0 };
  fd_snp_app_t client_app[1] = { 0 };
  uchar client_packet[FD_SNP_MTU] = { 0 };
  uint client_ip4 = 0UL;
  int client_sz = 0;
  fd_snp_meta_t client_meta = 0UL;
  int client_cb_res = 0;
  ulong client_msg_sz = 5UL;
  uchar * client_msg = (uchar *)"hello";

  void * client_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( &limits ), 1UL );
  fd_snp_t * client = fd_snp_join( fd_snp_new( client_mem, &limits ) );

  client->cb.rx = test_cb_snp_rx;
  client->cb.tx = test_cb_snp_tx;
  client->cb.ctx = client_cb_test;
  client_cb_test->out_packet = client_packet;
  client->apps_cnt = 1;
  client->apps[0].port = client_port;
  FD_TEST( fd_snp_init( client ) );

  client_app->cb.rx = test_cb_app_rx;
  client_app->cb.ctx = client_cb_test;

  /* Server */
  ushort server_port = 4567;
  test_cb_ctx_t server_cb_test[1] = { 0 };
  fd_snp_app_t server_app[1] = { 0 };
  uchar server_packet[FD_SNP_MTU] = { 0 };
  uint server_ip4 = 0UL;
  int server_sz = 0UL;
  fd_snp_meta_t server_meta = 0UL;
  int server_cb_res = 0;
  ulong server_msg_sz = 6UL;
  uchar * server_msg = (uchar *)"world!";

  void * server_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( &limits ), 1UL );
  fd_snp_t * server = fd_snp_join( fd_snp_new( server_mem, &limits ) );

  server->cb.tx = test_cb_snp_tx;
  server->cb.rx = test_cb_snp_rx;
  server->cb.ctx = server_cb_test;
  server_cb_test->out_packet = server_packet;
  server->apps_cnt = 1;
  server->apps[0].port = server_port;
  FD_TEST( fd_snp_init( server ) );

  server_app->cb.rx = test_cb_app_rx;
  server_app->cb.ctx = server_cb_test;

  /* Test protocol */

  /* Client sends */
  client_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, server_ip4, server_port );
  client_sz = fd_snp_app_send( client_app, client_packet, FD_SNP_MTU, client_msg, client_msg_sz, client_meta );
  assert( client_sz>0 );
  client_sz = fd_snp_send( client, client_packet, (ulong)client_sz, client_meta );
  assert( client_sz>0 );

  /* simulate network */ server_sz = client_sz; memcpy( server_packet, client_packet, (ulong)client_sz );
  FD_LOG_HEXDUMP_WARNING(( "packet", server_packet, (ulong)server_sz ));

  /* Server receives */
  server_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, client_ip4, client_port );

  server_cb_test->assert_packet = server_packet;
  server_cb_test->assert_packet_sz = (ulong)server_sz;
  server_cb_test->assert_meta = server_meta;
  server_cb_res = fd_snp_process_packet( server, server_packet, (ulong)server_sz );
  assert( server_cb_res==1 );

  server_cb_test->assert_peer = 0UL; //FIXME
  server_cb_test->assert_data = client_msg;
  server_cb_test->assert_data_sz = client_msg_sz;
  server_cb_test->assert_meta = server_meta;
  server_cb_res = fd_snp_app_recv( server_app, server_packet, (ulong)server_sz, server_meta );
  assert( server_cb_res==1 );

  /* Server sends */
  server_sz = fd_snp_app_send( server_app, server_packet, FD_SNP_MTU, server_msg, server_msg_sz, server_meta );
  assert( server_sz>0 );
  server_sz = fd_snp_send( server, server_packet, (ulong)server_sz, server_meta );
  assert( server_sz>0 );

  /* simulate network */ client_sz = server_sz; memcpy( client_packet, server_packet, (ulong)server_sz );
  FD_LOG_HEXDUMP_WARNING(( "packet", client_packet, (ulong)client_sz ));

  /* Client receives */
  client_cb_test->assert_packet = client_packet;
  client_cb_test->assert_packet_sz = (ulong)client_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_process_packet( client, client_packet, (ulong)client_sz );
  assert( client_cb_res==1 );

  client_cb_test->assert_peer = 0UL; //FIXME
  client_cb_test->assert_data = server_msg;
  client_cb_test->assert_data_sz = server_msg_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_app_recv( client_app, client_packet, (ulong)client_sz, client_meta );
  assert( client_cb_res==1 );

  FD_LOG_NOTICE(( "Test snp_app proto=udp: ok" ));
}

static void
test_snp_app_send_recv_v1( fd_wksp_t * wksp ) {
  ulong proto = FD_SNP_META_PROTO_V1;
  fd_snp_limits_t limits = { .conn_cnt = 256 };

  /* Client */
  ushort client_port = 1234;
  test_cb_ctx_t client_cb_test[1] = { 0 };
  fd_snp_app_t client_app[1] = { 0 };
  uchar client_packet[FD_SNP_MTU] = { 0 };
  uint client_ip4 = 0UL;
  int client_sz = 0;
  fd_snp_meta_t client_meta = 0UL;
  int client_cb_res = 0;
  ulong client_msg_sz = 5UL;
  uchar * client_msg = (uchar *)"hello";

  void * client_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( &limits ), 1UL );
  fd_snp_t * client = fd_snp_join( fd_snp_new( client_mem, &limits ) );

  client->cb.rx = test_cb_snp_rx;
  client->cb.tx = test_cb_snp_tx;
  client->cb.sign = test_cb_snp_sign;
  client->cb.ctx = client_cb_test;
  client_cb_test->out_packet = client_packet;
  external_generate_keypair( client_cb_test->private_key, client_cb_test->public_key );
  client_cb_test->snp = client;
  client->apps_cnt = 1;
  client->apps[0].port = client_port;
  FD_TEST( fd_snp_init( client ) );

  client_app->cb.rx = test_cb_app_rx;
  client_app->cb.ctx = client_cb_test;

  /* Server */
  ushort server_port = 4567;
  test_cb_ctx_t server_cb_test[1] = { 0 };
  fd_snp_app_t server_app[1] = { 0 };
  uchar server_packet[FD_SNP_MTU] = { 0 };
  uint server_ip4 = 0UL;
  int server_sz = 0UL;
  fd_snp_meta_t server_meta = 0UL;
  int server_cb_res = 0;
  ulong server_msg_sz = 6UL;
  uchar * server_msg = (uchar *)"world!";

  void * server_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( &limits ), 1UL );
  fd_snp_t * server = fd_snp_join( fd_snp_new( server_mem, &limits ) );

  server->cb.tx = test_cb_snp_tx;
  server->cb.rx = test_cb_snp_rx;
  server->cb.sign = test_cb_snp_sign;
  server->cb.ctx = server_cb_test;
  server_cb_test->out_packet = server_packet;
  external_generate_keypair( server_cb_test->private_key, server_cb_test->public_key );
  server_cb_test->snp = server;
  server->apps_cnt = 1;
  server->apps[0].port = server_port;
  FD_TEST( fd_snp_init( server ) );

  server_app->cb.rx = test_cb_app_rx;
  server_app->cb.ctx = server_cb_test;

  /* Test protocol */

  /* Client sends */
  client_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, server_ip4, server_port );
  client_sz = fd_snp_app_send( client_app, client_packet, FD_SNP_MTU, client_msg, client_msg_sz, client_meta );
  assert( client_sz>0 );
  client_sz = fd_snp_send( client, client_packet, (ulong)client_sz, client_meta ); /* client_init */
  assert( client_sz>0 );

  /* Handshake - snp_app is not involved - don't really need to memcpy packet all the times */
  server_sz = fd_snp_process_packet( server, client_packet, (ulong)client_sz );    /* server_init */
  assert( server_sz>0 );
  client_sz = fd_snp_process_packet( client, client_packet, (ulong)server_sz );    /* client_cont */
  assert( client_sz>0 );

  assert( server_cb_test->buf_cnt==0 );
  assert( server_cb_test->sign_cnt==0 );
  server_sz = fd_snp_process_packet( server, client_packet, (ulong)client_sz );    /* server_fini */
  assert( server_sz>0 );
  assert( server_cb_test->buf_cnt==1 );
  assert( server_cb_test->sign_cnt==1 );
  assert( (ushort)server_sz==server_cb_test->buf_packet[0].data_sz );

  /* send buffered packet (server_fini): server_cb_test->buf_packet[0].data */
  assert( client_cb_test->buf_cnt==0 );
  assert( client_cb_test->sign_cnt==0 );
  client_sz = fd_snp_process_packet( client, server_cb_test->buf_packet[0].data, (ulong)server_sz );    /* client_fini */
  assert( client_cb_test->buf_cnt==2 );
  assert( client_cb_test->sign_cnt==1 );
  assert( client_sz>0 );
  assert( (ushort)client_sz==client_cb_test->buf_packet[0].data_sz );
#if 1
  /* send buffered packet (client_fini): client_cb_test->buf_packet[0].data */
  server_sz = fd_snp_process_packet( server, client_cb_test->buf_packet[0].data, (ulong)client_sz );    /* server_acpt */
  assert( server_sz==0 );

  /* send buffered packet (client_app_payload): client_cb_test->buf_packet[1].data */
  server_sz = (int)client_cb_test->buf_packet[1].data_sz;
  memcpy( server_packet, client_cb_test->buf_packet[1].data, (ulong)server_sz );

  /* Server receives */
  server_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, client_ip4, client_port );

  server_cb_test->assert_packet = server_packet;
  server_cb_test->assert_packet_sz = (ulong)server_sz;
  server_cb_test->assert_meta = server_meta;
  FD_LOG_HEXDUMP_WARNING(( "packet", server_cb_test->assert_packet, (ulong)server_cb_test->assert_packet_sz ));
  server_cb_res = fd_snp_process_packet( server, server_packet, (ulong)server_sz );
  assert( server_cb_res==1 );
#else
  /* send buffered packet (client_app_payload): client_cb_test->buf_packet[1].data */
  server_sz = fd_snp_process_packet( server, client_cb_test->buf_packet[1].data, (ulong)client_cb_test->buf_packet[1].data_sz );    /* server_acpt */
  assert( server_sz==0 ); /* cache only */

  /* send buffered packet (client_fini): client_cb_test->buf_packet[1].data */
  server_sz = (int)client_cb_test->buf_packet[0].data_sz;
  memcpy( server_packet, client_cb_test->buf_packet[0].data, (ulong)server_sz );

  /* Server receives */
  server_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, client_ip4, client_port );

  /* Result is now buffered (from cache) */
  server_cb_test->assert_packet = client_cb_test->buf_packet[1].data;
  server_cb_test->assert_packet_sz = client_cb_test->buf_packet[1].data_sz;
  server_cb_test->assert_meta = server_meta | FD_SNP_META_OPT_BUFFERED;
  server_cb_test->assert_buffered = 1;
  assert( server_cb_test->buf_cnt==1 );
  FD_LOG_HEXDUMP_WARNING(( "packet", server_cb_test->assert_packet, (ulong)server_cb_test->assert_packet_sz ));
  server_cb_res = fd_snp_process_packet( server, server_packet, (ulong)server_sz );
  assert( server_cb_test->buf_cnt==2 );
  assert( server_cb_res==0 ); /* return is from processing server_acpt */
#endif

  server_cb_test->assert_peer = 0UL; //FIXME
  server_cb_test->assert_data = client_msg;
  server_cb_test->assert_data_sz = client_msg_sz;
  server_cb_test->assert_meta = server_meta;
  server_cb_res = fd_snp_app_recv( server_app, server_cb_test->assert_packet, (ulong)server_cb_test->assert_packet_sz, server_meta );
  assert( server_cb_res==1 );

  /* Server sends */
  server_sz = fd_snp_app_send( server_app, server_packet, FD_SNP_MTU, server_msg, server_msg_sz, server_meta );
  assert( server_sz>=0 );
  server_sz = fd_snp_send( server, server_packet, (ulong)server_sz, server_meta );
  assert( server_sz>0 );

  /* Handshake NOT needed a second time */

  /* simulate network */ client_sz = server_sz; memcpy( client_packet, server_packet, (ulong)server_sz );
  FD_LOG_HEXDUMP_WARNING(( "packet", client_packet, (ulong)client_sz ));

  /* Client receives */
  client_cb_test->assert_packet = client_packet;
  client_cb_test->assert_packet_sz = (ulong)client_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_process_packet( client, client_packet, (ulong)client_sz );
  assert( client_cb_res==1 );

  client_cb_test->assert_peer = 0UL; //FIXME
  client_cb_test->assert_data = server_msg;
  client_cb_test->assert_data_sz = server_msg_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_app_recv( client_app, client_packet, (ulong)client_sz, client_meta );
  assert( client_cb_res==1 );

  FD_LOG_NOTICE(( "Test snp_app proto=v1: ok" ));
}

static void
test_snp_app_send_recv_v2( void ) {
  ulong proto = FD_SNP_META_PROTO_V2;

  /* Client */
  fd_snp_app_t client_app[1] = { 0 };
  uchar client_packet[FD_SNP_MTU] = { 0 };
  int client_sz = 0;
  fd_snp_meta_t client_meta = 0UL;
  ulong client_msg_sz = 5UL;
  uchar * client_msg = (uchar *)"hello";

  uint server_ip4 = 0UL;
  ushort server_port = 0UL;

  /* Test protocol */

  /* Client sends */
  client_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, server_ip4, server_port );
  client_sz = fd_snp_app_send( client_app, client_packet, FD_SNP_MTU, client_msg, client_msg_sz, client_meta );
  assert( client_sz==-1 ); /* Not implemented */

  FD_LOG_NOTICE(( "Test snp_app proto=v2: ok (not implemented)" ));
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1UL << 15, fd_shmem_cpu_idx( 0 ), "wksp", 0UL );
  FD_TEST( wksp );

  test_snp_app_send_recv_udp( wksp );
  test_snp_app_send_recv_v1( wksp );
  test_snp_app_send_recv_v2();

  fd_wksp_delete_anonymous( wksp );

  return 0;
}

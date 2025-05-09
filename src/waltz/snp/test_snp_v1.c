#define _POSIX_C_SOURCE 199309L

#include "fd_snp_v1.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static inline long
wallclock( void ) {
  struct timespec ts[1];
  clock_gettime( CLOCK_REALTIME, ts );
  return ((long)1e9)*((long)ts->tv_sec) + (long)ts->tv_nsec;
}

static inline void
bench_output( ulong iter, long dt ) {
  double ops  = ((double)iter) / ((double)dt) * 1e3;
  double ns   = ((double)dt) / ((double)iter);
  double gbps = ((float)(8UL*(70UL+1200UL)*iter)) / ((float)dt);
  fprintf( stderr, "Benchmarking ephemeral/key share generate\n" );
  fprintf( stderr, "\t%10.3f Gbps Ethernet equiv throughput / core\n", gbps );
  fprintf( stderr, "\t%10.3f Mpps / core\n", ops );
  fprintf( stderr, "\t%10.3f ns / op\n", ns );
}

void external_generate_keypair( uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  FD_TEST( fd_rng_secure( private_key, 32 )!=NULL );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );
}

void external_sign( uchar signature[64], uchar to_sign[32], uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  fd_ed25519_sign( signature, to_sign, 32, public_key, private_key, sha512 );
}

static void
test_v1_handshake( void ) {
#if 0
  /* Init server, server_hs */
  fd_snp_s0_server_params_t server[1] = {0};
  fd_snp_s0_server_hs_t server_hs[1] = {0};

  uchar server_private_key[32];
  external_generate_keypair( server_private_key, server->identity );
  FD_TEST( fd_rng_secure( server->state_enc_key, 16 )!=NULL );

  /* Init client, client_hs */
  fd_snp_s0_client_params_t client[1] = {0};
  fd_snp_s0_client_hs_t client_hs[1]; //fd_snp_s0_client_hs_new( client_hs );

  uchar client_private_key[32];
  external_generate_keypair( client_private_key, client->identity );

  /* Init ctx, sessions */

  snp_net_ctx_t ctx[1] = { 0 };

  uchar client_pkt[ FD_SNP_MTU ];
  uchar server_pkt[ FD_SNP_MTU ];
  uchar to_sign[ 32 ];
  uchar signature[ 64 ];

  long client_pkt_sz;
  long server_pkt_sz;

  assert( client_hs->state == 0 );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_snp_s0_client_initial( client, client_hs, client_pkt );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == SNP_TYPE_HS_SERVER_CONTINUE );

  server_pkt_sz = fd_snp_s0_server_handle_initial( server, ctx, (snp_s0_hs_pkt_t *)client_pkt, server_pkt, server_hs );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == 0 );

  client_pkt_sz = fd_snp_s0_client_handle_continue( client, (snp_s0_hs_pkt_t *)server_pkt, client_pkt, to_sign, client_hs );
  external_sign( signature, to_sign, server_private_key, server->identity );
  fd_snp_s0_client_handle_continue_add_signature( client_pkt, signature );
  assert( client_pkt_sz>0L );
  assert( client_hs->state == SNP_TYPE_HS_SERVER_ACCEPT );

  server_pkt_sz = fd_snp_s0_server_handle_accept( server, ctx, (snp_s0_hs_pkt_t *)client_pkt, server_pkt, to_sign, server_hs );
  external_sign( signature, to_sign, server_private_key, server->identity );
  fd_snp_s0_server_handle_accept_add_signature( server_pkt, signature );
  assert( server_pkt_sz>0L );
  assert( server_hs->state == SNP_TYPE_HS_DONE );

  uchar scratch[sizeof(fd_snp_t)];
  fd_snp_t * snp = (fd_snp_t *)scratch;

  client_pkt_sz = fd_snp_s0_client_handle_accept( snp, client, (snp_s0_hs_pkt_t *)server_pkt, client_hs );
  assert( client_pkt_sz==0L );
  assert( client_hs->state == SNP_TYPE_HS_DONE );
  // assert( priv->sessions[0].session_id == FD_LOAD( ulong, client_hs->session_id ) );
#endif
  fd_snp_config_t client[1] = { 0 };
  fd_snp_conn_t   client_conn[1] = { 0 };
  uchar           client_private_key[ 32 ];

  fd_snp_config_t server[1] = { 0 };
  fd_snp_conn_t   server_conn[1] = { 0 };
  uchar           server_private_key[ 32 ];

  /* client init */
  external_generate_keypair( client_private_key, client->identity );
  client_conn->_pubkey = client->identity;

  /* server init */
  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, server->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, server->_state_dec_key );

  external_generate_keypair( server_private_key, server->identity );
  server_conn->_pubkey = server->identity;

  int   res;
  int   pkt_sz;
  uchar pkt[ 1500 ];
  uchar to_sign[ 32 ];
  uchar sig[ 64 ];

  pkt_sz = fd_snp_v1_client_init( client, client_conn, NULL, 0, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_init failed" );
  pkt_sz = fd_snp_v1_server_init( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_init failed" );
  pkt_sz = fd_snp_v1_client_cont( client, client_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_cont failed" );
  pkt_sz = fd_snp_v1_server_fini( server, server_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_server_fini failed" );
  external_sign( sig, to_sign, server_private_key, server->identity );
  res = fd_snp_v1_server_fini_add_signature( server_conn, pkt, sig );
  FD_TEST_CUSTOM( res==0, "fd_snp_v1_server_fini_add_signature failed" );
  pkt_sz = fd_snp_v1_client_fini( client, client_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
  FD_TEST_CUSTOM( pkt_sz>0, "fd_snp_v1_client_fini failed" );
  external_sign( sig, to_sign, client_private_key, client->identity );
  res = fd_snp_v1_client_fini_add_signature( client_conn, pkt, sig );
  FD_TEST_CUSTOM( res==0, "fd_snp_v1_client_fini_add_signature failed" );
  pkt_sz = fd_snp_v1_server_acpt( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
  FD_TEST_CUSTOM( pkt_sz==0, "fd_snp_v1_server_acpt failed" );

  FD_LOG_NOTICE(( "Test v1 handshake: ok" ));

  /* Bench */
  unsigned long iter = 20000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    pkt_sz = fd_snp_v1_client_init( client, client_conn, NULL, 0, pkt, NULL );
    pkt_sz = fd_snp_v1_server_init( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    pkt_sz = fd_snp_v1_client_cont( client, client_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    pkt_sz = fd_snp_v1_server_fini( server, server_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
    external_sign( sig, to_sign, server_private_key, server->identity );
    res = fd_snp_v1_server_fini_add_signature( server_conn, pkt, sig );
    pkt_sz = fd_snp_v1_client_fini( client, client_conn, pkt, (ulong)pkt_sz, pkt, to_sign );
    external_sign( sig, to_sign, client_private_key, client->identity );
    res = fd_snp_v1_client_fini_add_signature( client_conn, pkt, sig );
    pkt_sz = fd_snp_v1_server_acpt( server, server_conn, pkt, (ulong)pkt_sz, pkt, NULL );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (pkt[0]) );
  }
  dt += wallclock();
  bench_output( iter, dt );
}

static void
bench_ephemeral_generate( void ) {

  uchar public_key[32];
  uchar private_key[32];

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_key_share_generate( private_key, public_key );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (private_key[0]) );
  }

  /* for real */
  unsigned long iter = 2000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_key_share_generate( private_key, public_key );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (private_key[0]) );
  }
  dt += wallclock();
  bench_output( iter, dt );
}

static void
bench_enc_state_generate( void ) {
  fd_snp_config_t config[1];
  fd_snp_conn_t   conn[1];
  uchar           out[16];

  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, config->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, config->_state_dec_key );
  conn->peer_addr = 123UL;

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_generate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }

  /* for real */
  unsigned long iter = 20000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_generate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }
  dt += wallclock();
  bench_output( iter, dt );
}

static void
bench_enc_state_verify( void ) {

  fd_snp_config_t config[1];
  fd_snp_conn_t   conn[1];
  uchar           out[16];

  uchar aes_key[16];
  FD_TEST( fd_snp_rng( aes_key, 16 )==16 );
  fd_aes_set_encrypt_key( aes_key, 128, config->_state_enc_key );
  fd_aes_set_decrypt_key( aes_key, 128, config->_state_dec_key );
  conn->peer_addr = 123UL;

  fd_snp_v1_crypto_enc_state_generate( config, conn, out );

  /* warmup */
  for( unsigned long rem=1000UL; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_validate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }

  /* for real */
  unsigned long iter = 20000UL;
  long          dt   = -wallclock();
  for( unsigned long rem=iter; rem; rem-- ) {
    fd_snp_v1_crypto_enc_state_validate( config, conn, out );
    __asm__ __volatile__( "# Compiler Barrier" : "+r" (out[0]) );
  }
  dt += wallclock();
  bench_output( iter, dt );
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  test_v1_handshake();
  bench_ephemeral_generate();
  bench_enc_state_generate();
  bench_enc_state_verify();

  return 0;
}

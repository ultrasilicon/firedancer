#include "fd_snp_v1.h"

#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"

void snp_gen_session_id(ulong * session_id)
{
  static fd_rng_t _rng[1];
  static int _done_init = 0;
  if( !_done_init ) {
    fd_rng_join( fd_rng_new( _rng, 3, 4 ) ); /* TODO - figure out correct args here */
    _done_init = 1;
  }

  *session_id = fd_rng_ulong( _rng );
#if 0
  ((uchar *)session_id)[3] = (uchar)0xDE;
  ((uchar *)session_id)[4] = (uchar)0xAD;
  ((uchar *)session_id)[5] = (uchar)0xBE;
  ((uchar *)session_id)[6] = (uchar)0xEF;
#endif
}

static inline void
fd_snp_rng( uchar * buf, ulong buf_sz ) {
  FD_TEST( fd_rng_secure( buf, buf_sz )!=NULL );
}

void
fd_snp_s0_crypto_key_share_generate( uchar private_key[32], uchar public_key[32] ) {
  fd_snp_rng( private_key, 32 );
  fd_x25519_public( public_key, private_key );
}

void
fd_snp_s0_crypto_enc_state_generate( uchar private_key_enc[48], uchar public_key[32], uchar const key[16] ) {
  uchar private_key[32];
  fd_snp_rng( private_key, 32 );
  fd_x25519_public( public_key, private_key );

  fd_aes_gcm_t aes_gcm[1];
  fd_aes_128_gcm_init( aes_gcm, key, public_key );
  fd_aes_gcm_encrypt( aes_gcm, private_key_enc, private_key, 32, NULL, 0, private_key_enc+32 );
}

int
fd_snp_s0_crypto_enc_state_verify( uchar private_key[32], uchar const private_key_enc[48], uchar const public_key[32], uchar const key[16] ) {
  uchar public_key_check[32];

  fd_aes_gcm_t aes_gcm[1];
  fd_aes_128_gcm_init( aes_gcm, key, public_key );
  if( FD_UNLIKELY( 1!=fd_aes_gcm_decrypt( aes_gcm, private_key_enc, private_key, 32, NULL, 0, private_key_enc+32 ) ) ) {
    return -1;
  };

  fd_x25519_public( public_key_check, private_key );
  if( FD_UNLIKELY( 0!=memcmp( public_key, public_key_check, 32 ) ) ) {
    return -1;
  }

  return 0;
}

int
fd_snp_v1_client_init( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  (void)pkt_in;
  (void)extra;

  /* Expect client state to be just initialized */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t * out = (snp_s0_hs_pkt_t *)pkt_out;
  fd_memset( out, 0, FD_SNP_MTU_MIN );
  out->hs.base.version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_INIT );
  out->hs.src_session_id = conn->session_id;

  /* client identity - useless? */
  fd_memcpy( out->identity, client->identity, SNP_ED25519_KEY_SZ );

  /* client token */
  fd_snp_rng( conn->client_token, SNP_TOKEN_SZ );
  fd_memcpy( out->client_token, conn->client_token, SNP_TOKEN_SZ );

  /* set next expected state */
  conn->state = FD_SNP_TYPE_HS_CLIENT_INIT;

  return FD_SNP_MTU_MIN;
}

int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  (void)conn;
  (void)extra;

  snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;
  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != FD_SNP_TYPE_HS_CLIENT_INIT ) ) {
    return -1;
  }

  ulong session_id = pkt->hs.src_session_id;

  /* Create key_share */
  uchar key_share[32];
  uchar key_share_private_enc[32+16];
  fd_snp_s0_crypto_enc_state_generate( key_share_private_enc, key_share, server->state_enc_key );

  /* Send back the cookie and our server identity */

  snp_s0_hs_pkt_server_continue_t * out = (snp_s0_hs_pkt_server_continue_t *)pkt_out;
  fd_memset( out, 0, FD_SNP_MTU_MIN );

  out->hs.base.version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_SERVER_INIT );
  out->hs.base.session_id = session_id;

  fd_memcpy( out->client_token, pkt->client_token, SNP_TOKEN_SZ  );
  fd_memcpy( out->key_share, key_share, 32 );
  fd_memcpy( out->key_share_enc, key_share_private_enc, 48 );

  /* Return info to user */

  return (int)FD_SNP_MTU_MIN;
}

int
fd_snp_v1_client_cont( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  (void)extra;

  /* Expect client state to be awaiting FD_SNP_TYPE_HS_CLIENT_INIT */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_CLIENT_INIT ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;
  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != FD_SNP_TYPE_HS_SERVER_INIT ) ) {
    return -1;
  }

  /* Check client token */
  snp_s0_hs_pkt_server_continue_t * in = (snp_s0_hs_pkt_server_continue_t *)pkt_in;
  if( FD_UNLIKELY( 0!=memcmp( in->client_token, conn->client_token, SNP_TOKEN_SZ ) ) ) {
    // return -1; // FIXME
  }

  /* Generate key_share */
  uchar key_share[32];
  uchar key_share_private[32];
  fd_snp_s0_crypto_key_share_generate( key_share_private, key_share );

  /* Compute shared_secret */
  uchar shared_secret_ee[32];
  fd_x25519_exchange( shared_secret_ee, key_share_private, in->key_share );

  /* FIXME: encrypt identity s */

  /* FIXME: prepare signature */

  /* assemble response */
  snp_s0_hs_pkt_client_accept_t * out = (snp_s0_hs_pkt_client_accept_t *)pkt_out;
  fd_memset( out, 0, FD_SNP_MTU_MIN );

  out->hs.base.version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_CONT );
  out->hs.src_session_id = conn->session_id;
  fd_memcpy( out->server_key_share, in->key_share, 32 );
  fd_memcpy( out->server_key_share_enc, in->key_share_enc, 48 );
  fd_memcpy( out->key_share, key_share, 32 );
  fd_memcpy( out->identity, client->identity, 32 ); //FIXME

  //FIXME
  // fd_memcpy( extra, shared_secret_ee, 32 );

  conn->state = FD_SNP_TYPE_HS_CLIENT_CONT;
  return (int)FD_SNP_MTU_MIN;
}

int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  /* Expect server state to be just initialized
     (because it wasn't modified by server_initial) */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;
  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
    return -1;
  }

  ulong session_id = pkt->hs.src_session_id;
  snp_s0_hs_pkt_client_accept_t * in = (snp_s0_hs_pkt_client_accept_t *)pkt_in;

  /* Decrypt and verify state */
  uchar key_share_private[32];
  if( FD_UNLIKELY( fd_snp_s0_crypto_enc_state_verify( key_share_private, in->server_key_share_enc, in->server_key_share, server->state_enc_key )<0 ) ) {
    // return -1; //FIXME
  }

  /* Compute shared_secret */
  uchar shared_secret_ee[32];
  fd_x25519_exchange( shared_secret_ee, key_share_private, in->key_share );

  /* FIXME: decrypt client identity s and signature sig */
  uchar client_identity[32];
  uchar signature[64];
  fd_memcpy( client_identity, in->identity, 32 );
  fd_memcpy( signature, in->signature, 64 );

  /* FIXME: verify signature */
  // if( FD_UNLIKELY( fd_ed25519_verify( ... )!=FD_ED25519_SUCCESS ) ) {
  //   return -1;
  // }

  /* FIXME: encrypt identity s */

  /* FIXME: prepare signature */

  /* Derive session ID */

  /* assemble response */

  snp_s0_hs_pkt_server_accept_t * out = (snp_s0_hs_pkt_server_accept_t *)pkt_out;
  fd_memset( out, 0, FD_SNP_MTU_MIN );

  out->hs.base.version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_SERVER_FINI );
  out->hs.base.session_id = session_id;
  out->hs.src_session_id = conn->session_id;
  fd_memcpy( out->identity, server->identity, 32 ); //FIXME

  //FIXME
  fd_memcpy( extra, shared_secret_ee, 32 );

  /* Return info to caller */

  conn->peer_session_id = session_id;
  conn->state = FD_SNP_TYPE_HS_SERVER_FINI_SIG;
  return (int)FD_SNP_MTU_MIN;
}

int
fd_snp_v1_client_fini( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  /* Expect client state to be awaiting FD_SNP_TYPE_HS_CLIENT_CONT */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;
  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != FD_SNP_TYPE_HS_SERVER_FINI ) ) {
    return -1;
  }
  ulong session_id = pkt->hs.src_session_id;

  /* Check client token */
  snp_s0_hs_pkt_server_continue_t * in = (snp_s0_hs_pkt_server_continue_t *)pkt_in;
  if( FD_UNLIKELY( 0!=memcmp( in->client_token, conn->client_token, SNP_TOKEN_SZ ) ) ) {
    // return -1; // FIXME
  }

  /* Generate key_share */
  uchar key_share[32];
  uchar key_share_private[32];
  fd_snp_s0_crypto_key_share_generate( key_share_private, key_share );

  /* Compute shared_secret */
  uchar shared_secret_ee[32];
  fd_x25519_exchange( shared_secret_ee, key_share_private, in->key_share );

  /* FIXME: encrypt identity s */

  /* FIXME: prepare signature */

  /* assemble response */
  snp_s0_hs_pkt_client_accept_t * out = (snp_s0_hs_pkt_client_accept_t *)pkt_out;
  fd_memset( out, 0, FD_SNP_MTU_MIN );

  out->hs.base.version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_HS_CLIENT_FINI );
  out->hs.base.session_id = session_id;
  // out->hs.src_session_id = conn->session_id;
  fd_memcpy( out->server_key_share, in->key_share, 32 );
  fd_memcpy( out->server_key_share_enc, in->key_share_enc, 48 );
  fd_memcpy( out->key_share, key_share, 32 );
  fd_memcpy( out->identity, client->identity, 32 ); //FIXME

  //FIXME
  fd_memcpy( extra, shared_secret_ee, 32 );

  conn->peer_session_id = session_id;
  conn->state = FD_SNP_TYPE_HS_CLIENT_FINI_SIG;
  return (int)FD_SNP_MTU_MIN;
}

int
fd_snp_v1_server_acpt( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ) {
  (void)server;
  (void)extra;
  (void)pkt_out;

  /* Expect client state to be awaiting FD_SNP_TYPE_HS_SERVER_INIT */
  if( FD_UNLIKELY( conn->state != FD_SNP_TYPE_HS_SERVER_FINI ) ) {
    return -1;
  }

  snp_s0_hs_pkt_t const * pkt = (snp_s0_hs_pkt_t const *)pkt_in;
  if( FD_UNLIKELY( snp_hdr_type( &pkt->hs.base ) != FD_SNP_TYPE_HS_CLIENT_FINI ) ) {
    return -1;
  }

  /* Check client token */
  snp_s0_hs_pkt_server_continue_t * in = (snp_s0_hs_pkt_server_continue_t *)pkt_in;
  if( FD_UNLIKELY( 0!=memcmp( in->client_token, conn->client_token, SNP_TOKEN_SZ ) ) ) {
    // return -1; // FIXME
  }

  conn->state = FD_SNP_TYPE_HS_DONE;
  return 0;
}

int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar pkt_out[ FD_SNP_MTU-42 ],
                                     uchar sig[ 64 ] ) {
  snp_s0_hs_pkt_server_accept_t * out = (snp_s0_hs_pkt_server_accept_t *)pkt_out;
  fd_memcpy( out->signature, sig, 64 );
  conn->state = FD_SNP_TYPE_HS_SERVER_FINI;
  return 0;
}

int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar pkt_out[ FD_SNP_MTU-42 ],
                                     uchar sig[ 64 ] ) {
  snp_s0_hs_pkt_client_accept_t * out = (snp_s0_hs_pkt_client_accept_t *)pkt_out;
  fd_memcpy( out->signature, sig, 64 );
  conn->state = FD_SNP_TYPE_HS_DONE;
  return 0;
}

int
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz ) {
  /* SNP */
  snp_hdr_t * udp_payload = (snp_hdr_t *)packet;
  udp_payload->version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_PAYLOAD );
  udp_payload->session_id = conn->peer_session_id;

  /* data is already set by fd_snp_app_send */

  /* compute MAC */
  memset( packet+packet_sz-16, 0x88, 16 );

  return (int)packet_sz;
}

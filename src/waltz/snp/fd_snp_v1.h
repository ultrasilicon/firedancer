#ifndef HEADER_snp_s0_client_h
#define HEADER_snp_s0_client_h

#include "fd_snp_proto.h"

typedef struct fd_snp_config fd_snp_s0_client_params_t;
typedef struct fd_snp_conn   fd_snp_s0_client_hs_t;

typedef struct fd_snp_config fd_snp_s0_server_params_t;
typedef struct fd_snp_conn   fd_snp_s0_server_hs_t;

struct __attribute__((packed)) fd_snp_v1_pkt_hs {
  uint  version;
  ulong session_id;
  ulong src_session_id;
};
typedef struct fd_snp_v1_pkt_hs fd_snp_v1_pkt_hs_t;

struct __attribute__((packed)) fd_snp_v1_pkt_hs_client {
  fd_snp_v1_pkt_hs_t hs;
  union {
    struct {
      uchar          e[ 32 ];           /* client_init */
      uchar          r[ 16 ];           /* client_cont */
    };
    struct {
      uchar          enc_s1  [ 32+16 ]; /* client_fini */
      uchar          enc_sig1[ 64+16 ];
    };
  };
};
typedef struct fd_snp_v1_pkt_hs_client fd_snp_v1_pkt_hs_client_t;

struct __attribute__((packed)) fd_snp_v1_pkt_hs_server {
  fd_snp_v1_pkt_hs_t hs;
  uchar              r[ 16 ];         /* server_init */
  uchar              e[ 32 ];         /* server_fini */
  uchar              enc_s1  [ 32+16 ];
  uchar              enc_sig1[ 64+16 ];
};
typedef struct fd_snp_v1_pkt_hs_server fd_snp_v1_pkt_hs_server_t;

struct __attribute__((packed)) fd_snp_v1_pkt_hs_server_r {
  long   timestamp_ms;
  ulong  peer_addr;
};
typedef struct fd_snp_v1_pkt_hs_server_r fd_snp_v1_pkt_hs_server_r_t;
FD_STATIC_ASSERT( sizeof(fd_snp_v1_pkt_hs_server_r_t)==16UL, fd_snp_v1_pkt_hs_server_r_t );

FD_PROTOTYPES_BEGIN

int
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

int
fd_snp_v1_client_init( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,  // not used
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,    // not used
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_client_cont( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // to sign

int
fd_snp_v1_client_fini( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // to sign

int
fd_snp_v1_server_acpt( fd_snp_config_t const * server,  // not used
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       ulong                   pkt_in_sz,
                       uchar *                 pkt_out, // not used
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar const sig[ 64 ] );

FD_PROTOTYPES_END

#endif /* HEADER_snp_s0_client_h */

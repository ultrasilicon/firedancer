#ifndef HEADER_snp_s0_client_h
#define HEADER_snp_s0_client_h

#include "fd_snp_proto.h"

typedef struct fd_snp_config fd_snp_s0_client_params_t;
typedef struct fd_snp_conn   fd_snp_s0_client_hs_t;

typedef struct fd_snp_config fd_snp_s0_server_params_t;
typedef struct fd_snp_conn   fd_snp_s0_server_hs_t;

FD_PROTOTYPES_BEGIN

int
fd_snp_v1_finalize_packet( fd_snp_conn_t * conn,
                           uchar *         packet,
                           ulong           packet_sz );

int
fd_snp_v1_client_init( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,  // not used
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_init( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,    // not used
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_client_cont( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_fini( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // to sign

int
fd_snp_v1_client_fini( fd_snp_config_t const * client,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // to sign

int
fd_snp_v1_server_acpt( fd_snp_config_t const * server,
                       fd_snp_conn_t *         conn,
                       uchar const *           pkt_in,
                       uchar *                 pkt_out,
                       uchar *                 extra ); // not used

int
fd_snp_v1_server_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar sig[ 64 ] );

int
fd_snp_v1_client_fini_add_signature( fd_snp_conn_t * conn,
                                     uchar out[ FD_SNP_MTU-42 ],
                                     uchar sig[ 64 ] );

FD_PROTOTYPES_END

#endif /* HEADER_snp_s0_client_h */

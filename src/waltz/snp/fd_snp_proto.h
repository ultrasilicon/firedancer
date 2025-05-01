#ifndef HEADER_snp_proto_h
#define HEADER_snp_proto_h

/* snp_proto.h defines SNP protocol data structures. */

#include "../../util/fd_util_base.h"

/* SNP_MTU controls the maximum supported UDP payload size. */

//TODO: FD_SNP_MTU is currently 24 x 64
#define FD_SNP_MTU     (1536UL)
#define FD_SNP_MTU_MIN (1200UL)

#define FD_SNP_ALIGN   (128UL)
#define FD_SNP_ALIGNED __attribute__((aligned(128UL)))

/* SNP_V{...} identify SNP versions. */

#define FD_SNP_V1  ((uchar)0x01)

/* SNP_TYPE_{...} identify SNP packet types. */

#define FD_SNP_TYPE_NULL               ((uchar)0x00) /* invalid */

#define FD_SNP_TYPE_HS_CLIENT_INIT     ((uchar)0x01)
#define FD_SNP_TYPE_HS_SERVER_INIT     ((uchar)0x02)
#define FD_SNP_TYPE_HS_CLIENT_CONT     ((uchar)0x03)
#define FD_SNP_TYPE_HS_SERVER_FINI     ((uchar)0x04)
#define FD_SNP_TYPE_HS_CLIENT_FINI     ((uchar)0x05)
#define FD_SNP_TYPE_PAYLOAD            ((uchar)0x0F)

#define FD_SNP_TYPE_HS_SERVER_FINI_SIG ((uchar)0xF4) /* invalid on wire */
#define FD_SNP_TYPE_HS_CLIENT_FINI_SIG ((uchar)0xF5) /* invalid on wire */
#define FD_SNP_TYPE_HS_DONE            ((uchar)0xFF) /* invalid on wire */

/* SNP_SUITE_{...} defines cipher suite IDs.

   Each suite consists of:
   - A signature scheme for authentication
   - A key exchange mechanism
   - An authenticated encrypted scheme
   - A hash function for key expansion */

#define SNP_SUITE_S0  ((ushort)0x0000)  /* Ed25519 auth, unencrypted */
#define SNP_SUITE_S1  ((ushort)0x0001)  /* Ed25519 auth, X25519 KEX, AES-128-GCM AEAD, HMAC-SHA256 hash */

/* SNP_SESSION_ID_SZ is the byte size of the session ID. */

#define SNP_SESSION_ID_SZ (8UL)

/* SNP_COOKIE_SZ is the cookie byte size used in the handshake
   mechanism.  (Handshake cookies are analogous to TCP SYN cookies). */

#define SNP_COOKIE_SZ (8UL)

#define SNP_COOKIE_KEY_SZ (16UL)

#define SNP_ED25519_KEY_SZ (32UL)
#define SNP_STATE_KEY_SZ   (16UL)

#define FD_SNP_TO_SIGN_SZ  (40UL)

/* SNP_MAC_SZ is the byte size of the MAC tag in authenticated packets */

#define SNP_MAC_SZ (16UL)

/* SNP_BASIC_PAYLOAD_MTU is the MTU of the payload carried by the
   0x1 frame type */

#define SNP_BASIC_PAYLOAD_MTU (FD_SNP_MTU - SNP_SESSION_ID_SZ - SNP_MAC_SZ - 1)

#define FD_SNP_MAX_BUF (2UL)

#define FD_SNP_MAX_SESSION_TMP (3)

#define FD_SNP_MAGIC (0xdeadbeeffeebdaedUL)



struct fd_snp_config {
  double tick_per_us;  /* tick_per_us: clock ticks per microsecond */
  long   keep_alive_ms;
  long   handshake_retry_ms;

  /* identity pubkey */
  uchar identity[ SNP_ED25519_KEY_SZ ];

  /* random AES-128 key to encrypt state (to avoid storing state) */
  uchar state_enc_key[ SNP_STATE_KEY_SZ ];
};
typedef struct fd_snp_config fd_snp_config_t;


/* Packets */

struct FD_SNP_ALIGNED fd_snp_pkt {
  ulong next; // fd_pool

  /* only used by packets cache */
  ulong  session_id;
  uchar  send; // send or recv

  /* used both by packets cache, and last sent packets */
  ushort data_sz;
  uchar  data[ FD_SNP_MTU ];

  uchar _padding[ 490 ]; /* force sizeof(fd_snp_pkt_t)==2048 for feng shui (cf fd_pool.c) */
};
typedef struct fd_snp_pkt fd_snp_pkt_t;
FD_STATIC_ASSERT( sizeof(fd_snp_pkt_t)==2048UL, fd_snp_pkt_t );

#define POOL_NAME      fd_snp_pkt_pool
#define POOL_T         fd_snp_pkt_t
#include "../../util/tmpl/fd_pool.c"

/* Connections */

#define FD_SNP_STATE_INVALID     (0x00)
#define FD_SNP_STATE_CLIENT_INIT (0x01)
#define FD_SNP_STATE_SERVER_INIT (0x02)
#define FD_SNP_STATE_CLIENT_CONT (0x03)
#define FD_SNP_STATE_SERVER_FINI (0x04)
#define FD_SNP_STATE_CLIENT_FINI (0x05)
#define FD_SNP_STATE_ESTABLISHED (0xFF)

/* SNP_TOKEN_SZ is the byte size of the "random token" value.  Both
   client and server mix in their token value into the handshake
   commitment to prevent replay attacks. */
#define SNP_TOKEN_SZ (16UL)

struct FD_SNP_ALIGNED fd_snp_conn {
  ulong next; // fd_pool

  ulong session_id;
  ulong peer_addr;
  ulong peer_session_id;
  uchar state;

  fd_snp_pkt_t * last_pkt;

  uint is_server : 1;

  long last_sent_ts;

  // handshake
  uchar client_token[ SNP_TOKEN_SZ ];
};
typedef struct fd_snp_conn fd_snp_conn_t;

#define POOL_NAME      fd_snp_conn_pool
#define POOL_T         fd_snp_conn_t
#include "../../util/tmpl/fd_pool.c"

struct __attribute__((aligned(16))) fd_snp_conn_map {
  ulong           key;
  fd_snp_conn_t * val;
};
typedef struct fd_snp_conn_map fd_snp_conn_map_t;

#define MAP_NAME        fd_snp_conn_map
#define MAP_T           fd_snp_conn_map_t
#define MAP_MEMOIZE     0
#define MAP_HASH_T      ulong
#define MAP_KEY_HASH(k) (k)
#include "../../util/tmpl/fd_map_dynamic.c"






struct fd_snp_payload {
   ushort sz;
   uchar  data[SNP_BASIC_PAYLOAD_MTU];
};

typedef struct fd_snp_payload fd_snp_payload_t;

/* snp_hdr_t is the common SNP header shared by all packets. */

struct __attribute__((packed)) snp_hdr {
  uint  version_type;
  ulong session_id;
};

typedef struct snp_hdr snp_hdr_t;

/* snp_hs_hdr_t is the SNP header shared by all handshake packets. */

struct __attribute__((packed)) snp_hs_hdr {
  snp_hdr_t base;
  ulong     src_session_id;
};

typedef struct snp_hs_hdr snp_hdr_hs_t;


FD_PROTOTYPES_BEGIN

/* snp_hdr_{version,type} extract the version and type fields from
   an snp_hdr_t. */

__attribute__((pure))
static inline uchar
snp_hdr_version( snp_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type >> 4 );
}

__attribute__((pure))
static inline uchar
snp_hdr_type( snp_hdr_t const * hdr ) {
  return (uchar)( hdr->version_type & 0x0F );
}

/* snp_hdr_version_type assembles the version_type compound field. */

__attribute__((const))
static inline uint
fd_snp_hdr_version_type( uint version,
                         uint type ) {
  return (uchar)( ( version << 4 ) | ( type & 0x0F ) )
    | (uint)'S' << 8
    | (uint)'O' << 16
    | (uint)'L' << 24;
}

/* seq_{compress,expand} compress 64-bit sequence numbers to 32-bit
   compact versions and vice versa.

   seq_compress implements lossy compression by masking off the high
   half of the sequence number.

   seq_expand attempts to recover a 64-bit sequence given the
   compressed form (seq_compact), and the largest previously
   recovered sequence number (last_seq; does not necessarily have
   to be the previous packet).  For a given unreliable packet stream,
   seq_expand returns the correct result assuming conditions:

   1. The sequence number increments by one for each packet in the
      original order that the packets were sent in.
   2. Less than 2^31 packets were lost between the packet that
      yielded last_seq and the packet carrying seq_compact.
      (Otherwise, the returned sequence number is too small)
   3. The packet carrying seq_compact was reordered less than 2^31
      packets ahead.  (Otherwise, the returned sequence number is
      too large)

   The re-expanded packet number must be authenticated.  E.g.
   in SNP_SUITE_S1, it is part of the IV.  Thus, if an incorrect
   packet number is recovered, decryption fails.  Only sequence
   numbers that passed authentication sholud be considered for
   last_seq. */

static inline uint
seq_compress( ulong seq ) {
  return (uint)seq;
}

static inline ulong
seq_expand( uint seq_compact,
            ulong last_seq ) {
  /* O(3): 32-bit subtract, sign extend, 64-bit add */
  return last_seq + (ulong)(int)(seq_compact - (uint)last_seq);
}

FD_PROTOTYPES_END


/* Suite S0 structures ************************************************/

/* snp_s0_app_hdr_t is the SNP header of application unencrypted packets
   using SNP_SUITE_S0. */

typedef struct snp_hdr snp_s0_app_hdr_t;

/* snp_s0_hs_pkt_t is the SNP header of handshake packets using
   SNP_SUITE_S0. */

union __attribute__((packed)) snp_s0_hs_pkt {

  struct {
    snp_hdr_hs_t hs;

    uchar  identity[32];
    uchar  key_share[32];
    uchar  verify[64]; /* signature */
    uchar  client_token[ SNP_TOKEN_SZ ];
    uchar  server_token[ SNP_TOKEN_SZ ];
  };

  uchar raw[186];

};

typedef union snp_s0_hs_pkt snp_s0_hs_pkt_t;

struct snp_s0_hs_pkt_server_continue {
   snp_hdr_hs_t hs;

   uchar client_token[SNP_TOKEN_SZ];
   uchar key_share[32];     // e
   uchar key_share_enc[48]; // h
};
typedef struct snp_s0_hs_pkt_server_continue snp_s0_hs_pkt_server_continue_t;

struct snp_s0_hs_pkt_client_accept {
   snp_hdr_hs_t hs;

   uchar server_key_share[32];     // e
   uchar server_key_share_enc[48]; // h
   uchar key_share[32];  // e
   /* TODO: if this data is encrypted, it'll be bigger */
   uchar identity[32];   // s
   uchar signature[64];  // sig
};
typedef struct snp_s0_hs_pkt_client_accept snp_s0_hs_pkt_client_accept_t;

struct snp_s0_hs_pkt_server_accept {
   snp_hdr_hs_t hs;

   /* TODO: if this data is encrypted, it'll be bigger */
   uchar identity[32];  // s
   uchar signature[32]; // sig
};
typedef struct snp_s0_hs_pkt_server_accept snp_s0_hs_pkt_server_accept_t;

#endif /* HEADER_snp_proto_h */

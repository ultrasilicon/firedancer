#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_value_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_value_h

#include "../../util/fd_util.h"
#include "../../util/net/fd_net_headers.h"

#define FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP            ( 0)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC ( 1)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_RPC               ( 2)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_RPC_PUBSUB        ( 3)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR      ( 4)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU               ( 5)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS      ( 6)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC ( 7)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC          ( 8)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE          ( 9)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TVU               (10)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TVU_QUIC          (11)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC     (12)

#define FD_GOSSIP_CLIENT_SOLANA (0)
#define FD_GOSSIP_CLIENT_JITO   (1)
#define FD_GOSSIP_CLIENT_FD     (2)
#define FD_GOSSIP_CLIENT_AGAVE  (3)

#define FD_CRDS_TAG_LEGACY_CONTACT_INFO           ( 0)
#define FD_CRDS_TAG_VOTE                          ( 1)
#define FD_CRDS_TAG_LOWEST_SLOT                   ( 2)
#define FD_CRDS_TAG_SNAPSHOT_HASHES               ( 3)
#define FD_CRDS_TAG_ACCOUNT_HASHES                ( 4)
#define FD_CRDS_TAG_EPOCH_SLOTS                   ( 5)
#define FD_CRDS_TAG_LEGACY_VERSION_V1             ( 6)
#define FD_CRDS_TAG_LEGACY_VERSION_V2             ( 7)
#define FD_CRDS_TAG_NODE_INSTANCE                 ( 8)
#define FD_CRDS_TAG_DUPLICATE_SHRED               ( 9)
#define FD_CRDS_TAG_INC_SNAPSHOT_HASHES           (10)
#define FD_CRDS_TAG_CONTACT_INFO                  (11)
#define FD_CRDS_TAG_RESTART_LAST_VOTED_FORK_SLOTS (12)
#define FD_CRDS_TAG_RESTART_HEAVIEST_FORK         (13)

struct fd_crds_key {
  uchar tag;
  uchar pubkey[ 32UL ];
  union {
    uchar  vote_index;
    uchar  epoch_slots_index;
    ushort duplicate_shred_index;
  };
};

typedef struct fd_crds_key fd_crds_key_t;

struct fd_gossip_crds_contact_info {
  long   instance_creation_wallclock_nanos;
  ushort shred_version;

  struct {
    uchar client;

    ushort major;
    ushort minor;
    ushort patch;

    int   has_commit;
    uint  commit;
    uint  feature_set;
  } version;

  struct {
    /* WARNING: in gossip contact info message,
       ports are encoded in host form. The parser will
       perform the conversion */
    fd_ip4_port_t addr;
  } sockets[ 13UL ];
};

typedef struct fd_gossip_crds_contact_info fd_gossip_crds_contact_info_t;

struct fd_gossip_crds_vote {
  ulong   slot;
  uchar * txn; /* TODO: avoid pointers here */
  ulong   txn_sz;
};

typedef struct fd_gossip_crds_vote fd_gossip_crds_vote_t;

struct fd_gossip_crds_node_instance {
  uchar token[ 32UL ]; /* This is the node instance token */
  uchar from[ 32UL ];  /* This is the public key of the node that sent this message */
  ulong wallclock_nanos; /* Wallclock time when this message was created */
};
typedef struct fd_gossip_crds_node_instance fd_gossip_crds_node_instance_t;

struct fd_crds_value {
  /* The core operation of the CRDS is to "upsert" a value.  Basically,
     all of the message types are keyed by the originators public key,
     and we only want to store the most recent message of each type.

     So we have a ContactInfo message for example.  If a validator sends
     us a new ContactInfo message, we want to replace the old one.  This
     lookup is serviced by a hash table, keyed by the public key of the
     originator, and in a few special cases an additional field.  For
     example, votes are (originator_key, vote_index), since we need to
     know about more than one vote from a given originator.

     This key field is the key for the hash table. */
  fd_crds_key_t key[1];

  /* When an originator creates a CRDS message, they attach their local
     wallclock time to it.  This time is used to determine when a
     message should be upserted.  If messages have the same key, the
     newer one (as created by the originator) is used.

     Messages encode wallclock in millis, firedancer converts
     them into nanos internally. */
  long  wallclock_nanos;
  uchar signature[64UL]; /* signable data is always offset + sizeof(signature); signable_sz = sz - sizeof(signature) */
  union {
    fd_gossip_crds_contact_info_t  contact_info;
    fd_gossip_crds_vote_t          vote;
    fd_gossip_crds_node_instance_t node_instance;
  };
};
typedef struct fd_crds_value fd_crds_value_t;

FD_PROTOTYPES_BEGIN
long
fd_crds_value_wallclock( fd_crds_value_t const * value );

uchar const *
fd_crds_value_pubkey( fd_crds_value_t const * value );

uchar const *
fd_crds_value_hash( fd_crds_value_t const * value );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */

#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_private_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_private_h

#include "fd_gossip.h"
#include "fd_crds.h"

struct fd_gossip_private {
  uchar               identity_pubkey[ 32UL ];

  fd_gossip_metrics_t metrics[1];

  fd_crds_t *         crds;
  
};

#endif

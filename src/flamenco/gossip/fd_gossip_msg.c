#include "fd_gossip_msg.h"
#include "fd_gossip_types.h"
void
fd_gossip_msg_init( fd_gossip_message_t * msg ) {
  msg->tag = FD_GOSSIP_MESSAGE_LAST + 1; /* default to invalid message tag as a canary */
}

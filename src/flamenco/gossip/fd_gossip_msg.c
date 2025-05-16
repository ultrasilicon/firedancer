#include "fd_gossip_msg.h"
// #include "../../ballet/txn/fd_compact_u16.h"


/* Adapted from fd_txn_parse.c */
#define CHECK_INIT( payload, payload_sz )         \
  uchar const * _payload = (payload);             \
  ulong _payload_sz = (payload_sz);               \
  ulong _bytes_consumed = 0;                      \
  ulong i = 0;                                    \
  (void) _payload;                                \
  (void) _bytes_consumed;                         \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-i) )

// #define READ_CHECKED_COMPACT_U16( out_sz, var_name, where )                 \
//   do {                                                                      \
//     ulong _where = (where);                                                 \
//     ulong _out_sz = fd_cu16_dec_sz( _payload+_where, _payload_sz-_where );  \
//     CHECK( _out_sz );                                                       \
//     (var_name) = fd_cu16_dec_fixed( _payload+_where, _out_sz );             \
//     (out_sz)   = _out_sz;                                                   \
//   } while( 0 )

static ulong
fd_gossip_msg_ping_parse( fd_gossip_message_t * msg,
                          uchar const *         payload,
                          ulong                 payload_sz,
                          ulong *               payload_sz_opt ) {
  CHECK_INIT( payload, payload_sz      );
  fd_gossip_ping_t * ping = msg->ping;
  CHECK_LEFT( 32UL                     ); memcpy( ping->from,      payload+i, 32UL ); i+=32UL;  /* Pubkey */
  CHECK_LEFT( 32UL                     ); memcpy( ping->token,     payload+i, 32UL ); i+=32UL;  /* Token */
  CHECK_LEFT( 64UL                     ); memcpy( ping->signature, payload+i, 64UL ); i+=64UL;  /* Signature */
  
  /* metadata */
  fd_memcpy( msg->pubkey, ping->from, 32UL );
  fd_memcpy( msg->signature, ping->signature, 64UL );

  /* The token is the signable data */
  msg->has_signable_data    = 1;
  msg->signable_data_offset = 32UL;
  msg->signable_sz          = 32UL;

  return i;
}

static ulong
fd_gossip_msg_pong_parse( fd_gossip_message_t * msg,
                          uchar const *         payload,
                          ulong                 payload_sz,
                          ulong *               payload_sz_opt ) {
  CHECK_INIT( payload, payload_sz );
  fd_gossip_pong_t * pong = msg->pong;
  CHECK_LEFT( 32UL                ); memcpy( pong->from,      payload+i, 32UL ); i+=32UL; /* Pubkey */
  CHECK_LEFT( 32UL                ); memcpy( pong->hash,      payload+i, 32UL ); i+=32UL; /* Hash */
  CHECK_LEFT( 64UL                ); memcpy( pong->signature, payload+i, 64UL ); i+=64UL; /* Signature */

  /* metadata */
  fd_memcpy( msg->pubkey, pong->from, 32UL );
  fd_memcpy( msg->signature, pong->signature, 64UL );
  
  msg->has_signable_data    = 1;
  msg->signable_data_offset = 32UL;
  msg->signable_sz          = 32UL;
  
  return i;
}

ulong
fd_gossip_msg_parse( fd_gossip_message_t * msg,
                     uchar const *         payload,
                     ulong                 payload_sz,
                     ulong *               payload_sz_opt ) {
  CHECK_INIT( payload, payload_sz            );
  CHECK(      payload_sz<=FD_GOSSIP_MSG_MTU  );

  /* Extract enum discriminant/tag (4b encoded) */
  uint tag = 0;
  CHECK_LEFT( 4UL                            );   tag = payload[ i ];     i+=4;
  CHECK(      tag<FD_GOSSIP_MESSAGE_END      );
  msg->tag = (uchar)tag;

  ulong inner_decoded_sz = 0UL;
  switch( msg->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      break;
    case FD_GOSSIP_MESSAGE_PING:
      inner_decoded_sz = fd_gossip_msg_ping_parse( msg, payload+i, payload_sz-i, payload_sz_opt );
      CHECK( inner_decoded_sz==payload_sz-i );
      break;
    case FD_GOSSIP_MESSAGE_PONG:
      inner_decoded_sz = fd_gossip_msg_pong_parse( msg, payload+i, payload_sz-i, payload_sz_opt );
      CHECK( inner_decoded_sz==payload_sz-i );
      break;
    default:
      return 0;
  }
  i += inner_decoded_sz;
  CHECK( i<=payload_sz );

  /* Need to increment inner offsets by 4b to account for tag */
  msg->signable_data_offset += 4UL;
  for( ulong j=0; j<msg->crds_cnt; j++ ) {
    msg->crds[j].offset += 4UL;
  }
}

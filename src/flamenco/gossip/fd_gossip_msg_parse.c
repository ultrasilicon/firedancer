#include "fd_gossip_msg.h"
// #include "../../ballet/txn/fd_compact_u16.h"
#include "../../disco/fd_disco_base.h"


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
fd_gossip_msg_ping_pong_parse( fd_gossip_message_t * msg,
                               uchar const *         payload,
                               ulong                 payload_sz ) {
  CHECK_INIT( payload, payload_sz );
  fd_gossip_ping_pong_t * piong = msg->piong;
  CHECK_LEFT( 32UL                ); memcpy( piong->from,      payload+i, 32UL ); i+=32UL; /* Pubkey */
  CHECK_LEFT( 32UL                ); memcpy( piong->hash,      payload+i, 32UL ); i+=32UL; /* Token/Hash */
  CHECK_LEFT( 64UL                ); memcpy( piong->signature, payload+i, 64UL ); i+=64UL; /* Signature */

  /* metadata */
  fd_memcpy( msg->pubkey, piong->from, 32UL );
  fd_memcpy( msg->signature, piong->signature, 64UL );
  
  msg->has_non_crds_signable_data    = 1;
  msg->signable_data_offset = 32UL;
  msg->signable_sz          = 32UL;
  
  return i;
}

static ulong
fd_gossip_pull_req_parse( fd_gossip_message_t * msg,
                          uchar const *         payload,
                          ulong                 payload_sz ) {
  CHECK_INIT( payload, payload_sz );
  fd_gossip_pull_request_t * pull_request = msg->pull_request;

  /* Parse filter 
     FIXME: can we avoid memcpy and just pass offsets here? */
  fd_gossip_crds_filter_t * filter = pull_request->filter;
  /* parse bloom */
  fd_gossip_bloom_t * bloom = filter->bloom;
  CHECK_LEFT( 8UL                 ); bloom->keys_len = FD_LOAD( ulong, payload+i );            i+=8UL;
  CHECK_LEFT( bloom->keys_len*8UL ); fd_memcpy( bloom->keys, payload+i, bloom->keys_len*8UL ); i+=bloom->keys_len*8UL;

  uchar has_bits = 0;
  CHECK_LEFT( 1UL                 ); has_bits = FD_LOAD( uchar, payload+i );                   i++;
  if( has_bits ) {
    CHECK_LEFT( 8UL                 ); bloom->bits_len = FD_LOAD( ulong, payload+i );            i+=8UL;
    CHECK_LEFT( bloom->bits_len*8UL ); fd_memcpy( bloom->bits, payload+i, bloom->bits_len*8UL ); i+=bloom->bits_len*8UL;
    CHECK_LEFT( 8UL                 ); /* bits_len (TODO: check this vs bitvec len above?) */;   i+=8UL;
  } else {
    bloom->bits_len = 0UL;
  }
  CHECK_LEFT( 8UL                 ); bloom->num_bits_set = FD_LOAD( ulong, payload+i );        i+=8UL;

  CHECK_LEFT( 8UL                 ); filter->mask       = FD_LOAD( ulong, payload+i );         i+=8UL;
  CHECK_LEFT( 4UL                 ); filter->mask_bits  = FD_LOAD( uint, payload+i );          i+=4UL;
  
  /* Parse contact info */
  /* TODO: call parse_crds with crds_cnt = 1 */

  msg->has_non_crds_signable_data = 0; /* Signable data in contact info */



}

ulong
fd_gossip_msg_parse( fd_gossip_message_t * msg,
                     uchar const *         payload,
                     ulong                 payload_sz ) {
  CHECK_INIT( payload, payload_sz            );
  CHECK(      payload_sz<=FD_GOSSIP_MTU  );

  /* Extract enum discriminant/tag (4b encoded) */
  uint tag = 0;
  CHECK_LEFT( 4UL                            );   tag = payload[ i ];     i+=4;
  CHECK(      tag<=FD_GOSSIP_MESSAGE_LAST     );
  msg->tag = (uchar)tag;

  ulong inner_decoded_sz = 0UL;
  switch( msg->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
    case FD_GOSSIP_MESSAGE_PUSH:
    case FD_GOSSIP_MESSAGE_PRUNE:
      FD_LOG_ERR(( "Gossip message type %d parser not implemented", msg->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PING:
      inner_decoded_sz = fd_gossip_msg_ping_pong_parse( msg, payload+i, payload_sz-i );
      CHECK( inner_decoded_sz==payload_sz-i );
      break;
    default:
      return 0;
  }
  i += inner_decoded_sz;
  CHECK( i<=payload_sz );

  /* Need to increment inner offsets by 4b to account for tag
     TODO: make this less error prone (at this point message is technically validated) */
  msg->signable_data_offset += 4UL;
  for( ulong j=0; j<msg->crds_cnt; j++ ) {
    msg->crds[j].offset += 4UL;
  }
  return i;
}

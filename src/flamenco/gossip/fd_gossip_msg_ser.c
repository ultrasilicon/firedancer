#include "fd_gossip_private.h"
#include "../../util/bits/fd_bits.h"

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

int
fd_gossip_pull_request_encode_ctx_init( uchar *                               payload,
                                        ulong                                 payload_sz,
                                        ulong                                 num_keys,
                                        ulong                                 bloom_bits_cnt,
                                        fd_gossip_pull_request_encode_ctx_t * out_ctx ){
  CHECK_INIT( payload, payload_sz );
  CHECK_LEFT( 4UL ); FD_STORE( uint, payload+i, FD_GOSSIP_MESSAGE_PULL_REQUEST ); out_ctx->tag = payload+i; i+=4UL;
  CHECK_LEFT( 8UL ); FD_STORE( ulong, payload+i, num_keys ); out_ctx->bloom_keys_len = (ulong *)(payload+i); i+=8UL;
  CHECK_LEFT( 8UL*num_keys ); out_ctx->bloom_keys = (ulong *)(payload+i); i+=8UL*num_keys;
  if( FD_LIKELY( !!bloom_bits_cnt ) ) {
    /* Bloom bits is a bitvec<u64>, so we need to be careful about converting bloom bits count to vector lengths */
    ulong bloom_vec_len = (bloom_bits_cnt+63UL)/64UL;
    CHECK_LEFT( 1UL ); FD_STORE( uchar, payload+i, 1 ); out_ctx->has_bits = payload+i; i+=1UL;
    CHECK_LEFT( 8UL ); FD_STORE( ulong, payload+i, bloom_vec_len ); out_ctx->bloom_vec_len = (ulong *)(payload+i); i+=8UL;
    CHECK_LEFT( 8UL*bloom_vec_len ); out_ctx->bloom_bits = (ulong *)(payload+i); i+=8UL*bloom_vec_len;
    CHECK_LEFT( 8UL ); FD_STORE( ulong, payload+i, bloom_bits_cnt ); out_ctx->bloom_bits_count = (ulong *)(payload+i); i+=8UL;
    CHECK_LEFT( 8UL ); FD_STORE( ulong, payload+i, 0 ); out_ctx->bloom_num_bits_set = (ulong *)(payload+i); i+=8UL;
  } else {
    CHECK_LEFT( 1UL ); FD_STORE( uchar, payload+i, 0 ); out_ctx->has_bits = payload+i; i+=1UL;
    out_ctx->bloom_vec_len = NULL;
    out_ctx->bloom_bits = NULL;
    out_ctx->bloom_bits_count = NULL;
    out_ctx->bloom_num_bits_set = NULL;
  }
  CHECK_LEFT( 8UL ); FD_STORE( ulong, payload+i, 0 ); out_ctx->mask = (ulong *)(payload+i); i+=8UL;
  CHECK_LEFT( 4UL ); FD_STORE( uint, payload+i, 0 ); out_ctx->mask_bits = (ulong *)(payload+i); i+=4UL;
  out_ctx->contact_info = payload+i; /* Offset to the start of contact info in payload */

  return 0;
}

int
fd_gossip_pull_request_encode_bloom_keys( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_keys,
                                          ulong                                 bloom_keys_len ){
  /* This should break if encode ctx was not correctly initialized with bloom_keys_len */
  if( FD_UNLIKELY( *ctx->bloom_keys_len != bloom_keys_len ) ){
    FD_LOG_ERR(( "Bloom keys length mismatch: expected %lu, got %lu", *ctx->bloom_keys_len, bloom_keys_len ));
  }
  fd_memcpy( ctx->bloom_keys, bloom_keys, bloom_keys_len * sizeof(ulong) );
  return 0;
}

int
fd_gossip_pull_request_encode_bloom_bits( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_bits,
                                          ulong                                 bloom_bits_cnt ){
  if( FD_UNLIKELY( !ctx->has_bits || !ctx->bloom_vec_len || !ctx->bloom_bits ) ) {
    FD_LOG_ERR(( "Bloom bits not initialized in encode context" ));
  }
  if( FD_UNLIKELY( *ctx->bloom_bits_count != bloom_bits_cnt ) ){
    FD_LOG_ERR(( "Bloom bits length mismatch: expected %lu, got %lu", *ctx->bloom_bits_count, bloom_bits_cnt ));
  }

  fd_memcpy( ctx->bloom_bits, bloom_bits, *ctx->bloom_vec_len * sizeof(ulong) );
  return 0;
}

ulong
fd_gossip_init_msg_payload( uchar * payload,
                            ulong   payload_sz,
                            uchar   tag ) {
  CHECK_INIT( payload, payload_sz );
  CHECK_LEFT( 4UL ); /* Tag/Discriminant is actually 4b */
  if( FD_UNLIKELY( tag>FD_GOSSIP_MESSAGE_LAST ) ) {
    FD_LOG_ERR(( "Invalid message tag %d", tag ));
  }
  payload[i] = tag; i+=4UL;
  return i; /* Return size of payload so far */
}

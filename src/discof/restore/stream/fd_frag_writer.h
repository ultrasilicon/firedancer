#ifndef HEADER_fd_src_discof_restore_stream_fd_frag_writer_h
#define HEADER_fd_src_discof_restore_stream_fd_frag_writer_h

#include "../../../tango/mcache/fd_mcache.h"
#include "../../../disco/topo/fd_topo.h"

/* TODO: flesh out the rest of the API and docs */

struct fd_frag_writer {
  fd_frag_meta_t * mcache;
  ulong *          out_sync;
  ulong            depth;
  ulong            seq;
  ulong            chunk;

  ulong            chunk0;
  ulong            wmark;
  fd_wksp_t *      dcache_wksp;
};
typedef struct fd_frag_writer fd_frag_writer_t;

FD_PROTOTYPES_BEGIN

/* Constructor API ****************************************************/

/* fd_frag_writer_{align,footprint} describe a memory region suitable
   to hold a frag_writer. */

FD_FN_CONST static inline ulong
fd_frag_writer_align( void ) {
  return alignof(fd_frag_writer_t);
}

FD_FN_CONST static inline ulong
fd_frag_writer_footprint( void ) {
  return sizeof(fd_frag_writer_t);
}

fd_frag_writer_t *
fd_frag_writer_new( void *                 mem,
                    fd_topo_link_t *       link ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_frag_writer_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_frag_writer_t * writer    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_frag_writer_t), sizeof(fd_frag_writer_t) );

  writer->mcache      = link->mcache;
  writer->out_sync    = fd_mcache_seq_laddr( link->mcache );
  writer->seq         = fd_mcache_seq_query( writer->out_sync );
  writer->depth       = fd_mcache_depth( link->mcache );
  writer->chunk0      = fd_dcache_compact_chunk0( fd_wksp_containing( link->dcache ), link->dcache );
  writer->wmark       = fd_dcache_compact_wmark( fd_wksp_containing( link->dcache ), link->dcache, link->mtu );
  writer->chunk       = writer->chunk0;
  writer->dcache_wksp = fd_wksp_containing( link->dcache );
  return writer;
}

static inline uchar *
fd_frag_writer_prepare( fd_frag_writer_t * writer ) {
  return fd_chunk_to_laddr( writer->dcache_wksp, writer->chunk );
}

static inline void
fd_frag_writer_publish( fd_frag_writer_t * writer,
                        ulong              sz,
                        ulong              sig,
                        ulong              tsorig,
                        ulong              tspub,
                        ulong              ctl ) {
  fd_mcache_publish( writer->mcache,
                     writer->depth,
                     writer->seq,
                     sig,
                     writer->chunk,
                     sz,
                     ctl,
                     tsorig,
                     tspub );
  writer->seq = fd_seq_inc( writer->seq, 1UL );
  writer->chunk = fd_dcache_compact_next( writer->chunk, sz, writer->chunk0, writer->wmark );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_frag_writer_h */

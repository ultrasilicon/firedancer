#ifndef HEADER_fd_src_app_geys_filter_h
#define HEADER_fd_src_app_geys_filter_h

#include "geys_fd_loop.h"
#include "../../flamenco/types/fd_types.h"

typedef struct GeyserSubscribeReactor GeyserSubscribeReactor_t;

struct geys_filter;
typedef struct geys_filter geys_filter_t;

geys_filter_t * geys_filter_create(void);

void geys_filter_add_sub(geys_filter_t * filter, /* SubscribeRequest*/ void * request, GeyserSubscribeReactor_t * reactor);

void geys_filter_un_sub(geys_filter_t * filter, GeyserSubscribeReactor_t * reactor);

void geys_filter_acct(geys_filter_t * filter, ulong slot, fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz);

#endif /* HEADER_fd_src_app_geys_filter_h */

#ifndef HEADER_fd_src_app_geys_fd_loop_h
#define HEADER_fd_src_app_geys_fd_loop_h

#include "geys_history.h"

struct geys_fd_loop_args {
  geys_history_args_t history;
  char funk_file[ PATH_MAX ];
  char blockstore_wksp[ 32 ];
  char notify_wksp[ 32 ];
};

typedef struct geys_fd_loop_args geys_fd_loop_args_t;
typedef struct geys_fd_ctx geys_fd_ctx_t;

geys_fd_ctx_t * geys_fd_init( geys_fd_loop_args_t * args );

void geys_fd_loop( geys_fd_ctx_t * ctx );

geys_history_t * geys_fd_get_history( geys_fd_ctx_t * ctx );

#endif /* HEADER_fd_src_app_geys_fd_loop_h */

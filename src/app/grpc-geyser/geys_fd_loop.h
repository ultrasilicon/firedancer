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

void geys_fd_loop( geys_fd_loop_args_t * args );

#endif /* HEADER_fd_src_app_geys_fd_loop_h */

CPPFLAGS += -I/data/asiegel/pkg/include

LDFLAGS += /data/asiegel/pkg/lib/libgrpc++.a
LDFLAGS += /data/asiegel/pkg/lib64/libprotobuf.a
LDFLAGS += -Wl,--start-group $(wildcard /data/asiegel/pkg/lib64/libabsl_*.a) -Wl,--end-group
LDFLAGS += /data/asiegel/pkg/lib/libutf8_range_lib.a
LDFLAGS += /data/asiegel/pkg/lib64/libutf8_validity.a

$(call make-bin,fd_grpc_geyser,geyser.pb solana-storage.pb,fd_discof fd_disco fd_flamenco fd_reedsol fd_funk fd_tango fd_choreo fd_waltz fd_ballet fd_util,$(SECP256K1_LIBS))

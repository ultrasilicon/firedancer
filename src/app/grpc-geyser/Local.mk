PKG = /data/asiegel/pkg

CPPFLAGS += -I$(PKG)/include -Wno-conversion -Wno-pedantic -Wno-unused-parameter

LDFLAGS += -Wl,--start-group $(wildcard $(PKG)/lib/libgrpc*.a) -Wl,--end-group
LDFLAGS += -Wl,--start-group $(wildcard $(PKG)/lib/libupb_*.a) -Wl,--end-group
LDFLAGS += $(PKG)/lib/libgpr.a
LDFLAGS += $(PKG)/lib/libaddress_sorting.a
LDFLAGS += $(PKG)/lib/libcares.a
LDFLAGS += $(PKG)/lib/libre2.a
LDFLAGS += $(PKG)/lib/libssl.a
LDFLAGS += $(PKG)/lib/libcrypto.a
LDFLAGS += $(PKG)/lib/libz.a
LDFLAGS += $(PKG)/lib64/libprotobuf.a
LDFLAGS += -Wl,--start-group $(wildcard $(PKG)/lib64/libabsl_*.a) -Wl,--end-group
LDFLAGS += $(PKG)/lib/libutf8_range_lib.a
LDFLAGS += $(PKG)/lib64/libutf8_validity.a
LDFLAGS += -pthread -ldl -lsystemd

$(call make-bin,fd_grpc_geyser,geyser_server geyser.grpc.pb geyser.pb solana-storage.pb,fd_discof fd_disco fd_flamenco fd_reedsol fd_funk fd_tango fd_choreo fd_waltz fd_ballet fd_util,$(SECP256K1_LIBS))

$(call make-unit-test,test_geyser_client,test_geyser_client geyser.grpc.pb geyser.pb solana-storage.pb,fd_discof fd_disco fd_flamenco fd_reedsol fd_funk fd_tango fd_choreo fd_waltz fd_ballet fd_util,$(SECP256K1_LIBS))

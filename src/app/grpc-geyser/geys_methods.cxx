extern "C" {
#include "../firedancer/version.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../ballet/base58/fd_base58.h"
#include "geys_filter.h"
}

#include <mutex>

#include "geys_methods.hxx"
#include "geys_filter_2.hxx"

GeyserServiceImpl::GeyserServiceImpl(geys_fd_ctx_t * loop_ctx)
  : _loop_ctx(loop_ctx), filt_(geys_get_filter(loop_ctx))
{
  geys_filter_set_service(filt_, this);
}

GeyserServiceImpl::~GeyserServiceImpl() {
}

void
GeyserServiceImpl::notify(fd_replay_notif_msg_t * msg) {
  lastinfo_ = *msg;
}

::grpc::ServerBidiReactor<::geyser::SubscribeRequest, ::geyser::SubscribeUpdate>*
GeyserServiceImpl::Subscribe(::grpc::CallbackServerContext* context) {
  return new GeyserSubscribeReactor(this, filt_);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::SubscribeReplayInfo(::grpc::CallbackServerContext* context, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) {
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::Ping(::grpc::CallbackServerContext* context, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) {
        response->set_count( request->count() );
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::GetLatestBlockhash(::grpc::CallbackServerContext* context, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) {
        response->set_slot( serv->lastinfo_.slot_exec.slot );
        FD_BASE58_ENCODE_32_BYTES( serv->lastinfo_.slot_exec.block_hash.uc, hash_str );
        response->set_blockhash( std::string(hash_str, hash_str_len) );
        response->set_last_valid_block_height( serv->lastinfo_.slot_exec.height );
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::GetBlockHeight(::grpc::CallbackServerContext* context, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) {
        response->set_block_height( serv->lastinfo_.slot_exec.height );
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::GetSlot(::grpc::CallbackServerContext* context, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) {
        response->set_slot( serv->lastinfo_.slot_exec.slot );
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::IsBlockhashValid(::grpc::CallbackServerContext* context, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) {
        fd_hash_t hash;
        if( fd_base58_decode_32( request->blockhash().c_str(), hash.uc ) == NULL ) {
          Finish(grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "failed to decode hash"));
          return;
        }
        response->set_slot(serv->lastinfo_.slot_exec.slot);
        response->set_valid(true);
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

::grpc::ServerUnaryReactor*
GeyserServiceImpl::GetVersion(::grpc::CallbackServerContext* context, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) {
  class Reactor : public grpc::ServerUnaryReactor {
    public:
      Reactor(GeyserServiceImpl * serv, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) {
        response->set_version(FIREDANCER_VERSION);
        Finish(grpc::Status::OK);
      }
      void OnDone() override {
        delete this;
      }
  };
  return new Reactor(this, request, response);
}

#include "geys_methods.hxx"

extern "C" {
#include "../firedancer/version.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../ballet/base58/fd_base58.h"
}

GeyserServiceImpl::GeyserServiceImpl(geys_fd_ctx_t * loop_ctx)
  : _loop_ctx(loop_ctx), _hist_ctx(geys_fd_get_history(loop_ctx)) {
}

GeyserServiceImpl::~GeyserServiceImpl() {
}

::grpc::ServerBidiReactor< ::geyser::SubscribeRequest, ::geyser::SubscribeUpdate>*
GeyserServiceImpl::Subscribe(::grpc::CallbackServerContext* context) {
  return NULL;
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
        fd_replay_notif_msg_t * info = geys_history_get_block_info( serv->_hist_ctx, geys_history_latest_slot( serv->_hist_ctx ) );
        if( info == NULL ) { Finish(::grpc::Status(::grpc::StatusCode::INTERNAL, "missing block info")); return; }
        response->set_slot( info->slot_exec.slot );
        FD_BASE58_ENCODE_32_BYTES( info->slot_exec.block_hash.uc, hash_str );
        response->set_blockhash( std::string(hash_str, hash_str_len) );
        response->set_last_valid_block_height( info->slot_exec.height );
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
        fd_replay_notif_msg_t * info = geys_history_get_block_info( serv->_hist_ctx, geys_history_latest_slot( serv->_hist_ctx ) );
        if( info == NULL ) { Finish(::grpc::Status(::grpc::StatusCode::INTERNAL, "missing block info")); return; }
        response->set_block_height( info->slot_exec.height );
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
        response->set_slot( geys_history_latest_slot( serv->_hist_ctx ) );
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
        fd_replay_notif_msg_t * info = geys_history_get_block_info_by_hash( serv->_hist_ctx, &hash );
        if( info == NULL ) {
          response->set_valid(false);
        } else {
          response->set_slot(info->slot_exec.slot);
          response->set_valid(true);
        }
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

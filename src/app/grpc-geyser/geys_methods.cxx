extern "C" {
#include "../firedancer/version.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../ballet/base58/fd_base58.h"
#include "geys_filter.h"
}

#include <mutex>

#include "geys_methods.hxx"

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
  validhashes_[msg->slot_exec.block_hash] = msg->slot_exec.slot;
}

struct GeyserSubscribeReactor : public ::grpc::ServerBidiReactor<::geyser::SubscribeRequest, ::geyser::SubscribeUpdate> {
  GeyserSubscribeReactor(GeyserServiceImpl * serv, geys_filter_t * filter) : serv_(serv), filter_(filter) {
    std::scoped_lock smut(mut_);
    StartRead(&request_);
  }
  void OnReadDone(bool ok) override {
    std::scoped_lock smut(mut_);
    if (ok) {
      geys_filter_add_sub(filter_, &request_, this);
      StartRead(&request_);
    } else {
      Finish(::grpc::Status::OK);
    }
  }

  void Update(::geyser::SubscribeUpdate* update) {
    std::scoped_lock smut(mut_);
    if( updates_.empty() ) {
      StartWrite( update );
    }
    updates_.push_back(update);
  }

  void OnWriteDone(bool ok) override {
    std::scoped_lock smut(mut_);
    if (ok) {
      auto i = updates_.begin();
      delete (::geyser::SubscribeUpdate*)(*i);
      updates_.erase(i);
      if( !updates_.empty() ) {
        StartWrite( *updates_.begin() );
      }
    }
  }

  void OnDone() override {
    {
      std::scoped_lock smut(mut_);
      geys_filter_un_sub(filter_, this);
    }
    delete this;
  }

  std::mutex mut_;
  GeyserServiceImpl * serv_ = NULL;
  geys_filter_t * filter_ = NULL;
  ::geyser::SubscribeRequest request_;
  std::vector<::geyser::SubscribeUpdate*> updates_;
};

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
        auto i = serv->validhashes_.find(hash);
        if( i == serv->validhashes_.end() )
          response->set_valid(false);
        else {
          response->set_slot(i->second);
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

void
GeyserServiceImpl::updateAcct(GeyserSubscribeReactor_t * reactor, ulong slot, fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz) {
  auto* update = new ::geyser::SubscribeUpdate();
  auto* acct = new ::geyser::SubscribeUpdateAccount();
  update->set_allocated_account(acct);
  acct->set_slot(slot);
  acct->set_is_startup(false);
  auto* info = new ::geyser::SubscribeUpdateAccountInfo();
  acct->set_allocated_account(info);
  info->set_pubkey(key->uc, 32U);
  info->set_lamports(meta->info.lamports);
  info->set_owner(meta->info.owner, 32U);
  info->set_executable(meta->info.executable);
  info->set_data(val, val_sz);

  reactor->Update( update );
}

void
GeyserServiceImpl::updateSlot(GeyserSubscribeReactor_t * reactor, fd_replay_notif_msg_t * msg) {
  auto* update = new ::geyser::SubscribeUpdate();
  auto* slot = new ::geyser::SubscribeUpdateSlot();
  update->set_allocated_slot(slot);
  slot->set_slot(msg->slot_exec.slot);
  slot->set_parent(msg->slot_exec.parent);

  reactor->Update( update );
}

void
GeyserServiceImpl::updateTxn(GeyserSubscribeReactor_t * reactor, fd_txn_t * txn, fd_pubkey_t * accs, fd_ed25519_sig_t const * sigs) {
  auto* update = new ::geyser::SubscribeUpdate();
  auto* txn2 = new ::geyser::SubscribeUpdateTransaction();
  update->set_allocated_transaction(txn2);

  reactor->Update( update );
}

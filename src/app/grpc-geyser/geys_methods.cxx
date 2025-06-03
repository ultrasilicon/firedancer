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

::grpc::Status
GeyserServiceImpl::Subscribe(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::geyser::SubscribeUpdate, ::geyser::SubscribeRequest>* stream) {
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::SubscribeReplayInfo(::grpc::ServerContext* context, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::Ping(::grpc::ServerContext* context, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) {
  response->set_count( request->count() );
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::GetLatestBlockhash(::grpc::ServerContext* context, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) {
  fd_replay_notif_msg_t * info = geys_history_get_block_info( _hist_ctx, geys_history_latest_slot( _hist_ctx ) );
  if( info == NULL ) return ::grpc::Status(::grpc::StatusCode::INTERNAL, "missing block info");
  response->set_slot( info->slot_exec.slot );
  FD_BASE58_ENCODE_32_BYTES( info->slot_exec.block_hash.uc, hash_str );
  response->set_blockhash( std::string(hash_str, hash_str_len) );
  response->set_last_valid_block_height( info->slot_exec.height );
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::GetBlockHeight(::grpc::ServerContext* context, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) {
  fd_replay_notif_msg_t * info = geys_history_get_block_info( _hist_ctx, geys_history_latest_slot( _hist_ctx ) );
  if( info == NULL ) return ::grpc::Status(::grpc::StatusCode::INTERNAL, "missing block info");
  response->set_block_height( info->slot_exec.height );
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::GetSlot(::grpc::ServerContext* context, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) {
  response->set_slot( geys_history_latest_slot( _hist_ctx ) );
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::IsBlockhashValid(::grpc::ServerContext* context, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) {
  fd_hash_t hash;
  if( fd_base58_decode_32( request->blockhash().c_str(), hash.uc ) == NULL ) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "failed to decode hash");
  }
  fd_replay_notif_msg_t * info = geys_history_get_block_info_by_hash( _hist_ctx, &hash );
  if( info == NULL ) {
    response->set_valid(false);
  } else {
    response->set_slot(info->slot_exec.slot);
    response->set_valid(true);
  }
  return ::grpc::Status::OK;
}

::grpc::Status
GeyserServiceImpl::GetVersion(::grpc::ServerContext* context, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) {
  response->set_version(FIREDANCER_VERSION);
  return ::grpc::Status::OK;
}

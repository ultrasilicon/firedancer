#include "geys_methods.hxx"

extern "C" {
#include "../firedancer/version.h"
}

GeyserServiceImpl::GeyserServiceImpl() {
}

GeyserServiceImpl::~GeyserServiceImpl() {
}

::grpc::Status GeyserServiceImpl::Subscribe(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::geyser::SubscribeUpdate, ::geyser::SubscribeRequest>* stream) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::SubscribeReplayInfo(::grpc::ServerContext* context, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::Ping(::grpc::ServerContext* context, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) {
  response->set_count( request->count() );
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::GetLatestBlockhash(::grpc::ServerContext* context, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::GetBlockHeight(::grpc::ServerContext* context, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::GetSlot(::grpc::ServerContext* context, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::IsBlockhashValid(::grpc::ServerContext* context, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status GeyserServiceImpl::GetVersion(::grpc::ServerContext* context, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) {
  response->set_version(FIREDANCER_VERSION);
  return ::grpc::Status::OK;
}

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "geyser.grpc.pb.h"

extern "C" {
#include "geys_fd_loop.h"
#include "geys_history.h"
}

class GeyserServiceImpl final : public geyser::Geyser::Service {
    geys_fd_ctx_t * _loop_ctx;
    geys_history_t * _hist_ctx;

  public:
    GeyserServiceImpl(geys_fd_ctx_t * loop_ctx);

    virtual ~GeyserServiceImpl() override;

    virtual ::grpc::Status Subscribe(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::geyser::SubscribeUpdate, ::geyser::SubscribeRequest>* stream) override;

    virtual ::grpc::Status SubscribeReplayInfo(::grpc::ServerContext* context, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) override;

    virtual ::grpc::Status Ping(::grpc::ServerContext* context, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) override;

    virtual ::grpc::Status GetLatestBlockhash(::grpc::ServerContext* context, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) override;

    virtual ::grpc::Status GetBlockHeight(::grpc::ServerContext* context, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) override;

    virtual ::grpc::Status GetSlot(::grpc::ServerContext* context, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) override;

    virtual ::grpc::Status IsBlockhashValid(::grpc::ServerContext* context, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) override;

    virtual ::grpc::Status GetVersion(::grpc::ServerContext* context, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) override;
};

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "geyser.grpc.pb.h"

extern "C" {
#include "geys_fd_loop.h"
#include "geys_filter.h"
#include "../../discof/replay/fd_replay_notif.h"
}

class GeyserServiceImpl final : public geyser::Geyser::CallbackService{
    geys_fd_ctx_t * _loop_ctx;
    geys_filter_t * filt_;
    fd_replay_notif_msg_t lastinfo_;

  public:
    GeyserServiceImpl(geys_fd_ctx_t * loop_ctx);

    virtual ~GeyserServiceImpl() override;

    virtual ::grpc::ServerBidiReactor< ::geyser::SubscribeRequest, ::geyser::SubscribeUpdate>* Subscribe(
      ::grpc::CallbackServerContext* /*context*/) override;

    virtual ::grpc::ServerUnaryReactor* SubscribeReplayInfo(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::SubscribeReplayInfoRequest* /*request*/, ::geyser::SubscribeReplayInfoResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* Ping(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::PingRequest* /*request*/, ::geyser::PongResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* GetLatestBlockhash(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::GetLatestBlockhashRequest* /*request*/, ::geyser::GetLatestBlockhashResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* GetBlockHeight(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::GetBlockHeightRequest* /*request*/, ::geyser::GetBlockHeightResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* GetSlot(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::GetSlotRequest* /*request*/, ::geyser::GetSlotResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* IsBlockhashValid(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::IsBlockhashValidRequest* /*request*/, ::geyser::IsBlockhashValidResponse* /*response*/) override;

    virtual ::grpc::ServerUnaryReactor* GetVersion(
      ::grpc::CallbackServerContext* /*context*/, const ::geyser::GetVersionRequest* /*request*/, ::geyser::GetVersionResponse* /*response*/) override;

    void notify(fd_replay_notif_msg_t * msg);
};

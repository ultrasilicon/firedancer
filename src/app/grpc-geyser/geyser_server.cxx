#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/strings/str_format.h"

#include "geyser.grpc.pb.h"

extern "C" {
#include "../../util/fd_util.h"
#include "geys_fd_loop.h"
}

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

ABSL_FLAG(uint16_t, port, 8123, "Server port for the service");
ABSL_FLAG(std::string, funk_file, NULL, "Funk database file");
ABSL_FLAG(std::string, blockstore_wksp, "fd1_bstore.wksp", "Blockstore workspace");
ABSL_FLAG(std::string, notify_wksp, "fd1_replay_notif.wksp", "Notification link workspace");
ABSL_FLAG(int, max_block_idx, 65536, "Max number of blocks which can be indexed");
ABSL_FLAG(int, max_txn_idx, 1048576, "Max number of transactions which can be indexed");
ABSL_FLAG(int, max_acct_idx, 1048576, "Max number of accounts which can be indexed");
ABSL_FLAG(std::string, history_file, "geyser_history", "Storage for geyser history");

// Logic and data behind the server's behavior.
class GeyserServiceImpl final : public geyser::Geyser::Service {
  public:
    GeyserServiceImpl() {
    }

    virtual ~GeyserServiceImpl() override {
    }

    virtual ::grpc::Status Subscribe(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::geyser::SubscribeUpdate, ::geyser::SubscribeRequest>* stream) override {
      return Status::OK;
    }

    virtual ::grpc::Status SubscribeReplayInfo(::grpc::ServerContext* context, const ::geyser::SubscribeReplayInfoRequest* request, ::geyser::SubscribeReplayInfoResponse* response) override {
      return Status::OK;
    }

    virtual ::grpc::Status Ping(::grpc::ServerContext* context, const ::geyser::PingRequest* request, ::geyser::PongResponse* response) override {
      response->set_count( request->count() );
      return Status::OK;
    }

    virtual ::grpc::Status GetLatestBlockhash(::grpc::ServerContext* context, const ::geyser::GetLatestBlockhashRequest* request, ::geyser::GetLatestBlockhashResponse* response) override {
      return Status::OK;
    }

    virtual ::grpc::Status GetBlockHeight(::grpc::ServerContext* context, const ::geyser::GetBlockHeightRequest* request, ::geyser::GetBlockHeightResponse* response) override {
      return Status::OK;
    }

    virtual ::grpc::Status GetSlot(::grpc::ServerContext* context, const ::geyser::GetSlotRequest* request, ::geyser::GetSlotResponse* response) override {
      return Status::OK;
    }

    virtual ::grpc::Status IsBlockhashValid(::grpc::ServerContext* context, const ::geyser::IsBlockhashValidRequest* request, ::geyser::IsBlockhashValidResponse* response) override {
      return Status::OK;
    }

    virtual ::grpc::Status GetVersion(::grpc::ServerContext* context, const ::geyser::GetVersionRequest* request, ::geyser::GetVersionResponse* response) override {
      response->set_version(FIREDANCER_VERSION);
      return Status::OK;
    }
};

void RunServer(uint16_t port) {
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);
  GeyserServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  fd_boot( &argc, &argv );

  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  geys_fd_loop_args_t loop_args;
  loop_args.history.block_index_max = absl::GetFlag(FLAGS_max_block_idx);
  loop_args.history.txn_index_max = absl::GetFlag(FLAGS_max_txn_idx);
  loop_args.history.acct_index_max = absl::GetFlag(FLAGS_max_acct_idx);
  strncpy(loop_args.history.history_file, absl::GetFlag(FLAGS_history_file).c_str(), PATH_MAX);
  strncpy(loop_args.funk_file, absl::GetFlag(FLAGS_funk_file).c_str(), PATH_MAX);
  strncpy(loop_args.blockstore_wksp, absl::GetFlag(FLAGS_blockstore_wksp).c_str(), 32);
  strncpy(loop_args.notify_wksp, absl::GetFlag(FLAGS_notify_wksp).c_str(), 32);

  RunServer(absl::GetFlag(FLAGS_port));

  fd_halt();
  return 0;
}

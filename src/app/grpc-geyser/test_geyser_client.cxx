#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "geyser.grpc.pb.h"

ABSL_FLAG(std::string, target, "localhost:8754", "Server address");

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class GeyserClient {
  public:
    GeyserClient(std::shared_ptr<Channel> channel)
      : stub_(geyser::Geyser::NewStub(channel)) {}

    void testGetVersion() {
      // Data we are sending to the server.
      ::geyser::GetVersionRequest request;

      // Container for the data we expect from the server.
      ::geyser::GetVersionResponse reply;

      // Context for the client. It could be used to convey extra information to
      // the server and/or tweak certain RPC behaviors.
      ClientContext context;

      // The actual RPC.
      Status status = stub_->GetVersion(&context, request, &reply);

      // Act upon its status.
      if (status.ok()) {
        std::cout << "version=" << reply.version() << std::endl;
      } else {
        std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      }
    }

    void testPing() {
      // Data we are sending to the server.
      ::geyser::PingRequest request;
      request.set_count(1234);

      // Container for the data we expect from the server.
      ::geyser::PongResponse reply;

      // Context for the client. It could be used to convey extra information to
      // the server and/or tweak certain RPC behaviors.
      ClientContext context;

      // The actual RPC.
      Status status = stub_->Ping(&context, request, &reply);

      // Act upon its status.
      if (status.ok()) {
        std::cout << "pong=" << reply.count() << std::endl;
      } else {
        std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      }
    }

    void testGetSlot() {
      // Data we are sending to the server.
      ::geyser::GetSlotRequest request;

      // Container for the data we expect from the server.
      ::geyser::GetSlotResponse reply;

      // Context for the client. It could be used to convey extra information to
      // the server and/or tweak certain RPC behaviors.
      ClientContext context;

      // The actual RPC.
      Status status = stub_->GetSlot(&context, request, &reply);

      // Act upon its status.
      if (status.ok()) {
        std::cout << "slot=" << reply.slot() << std::endl;
      } else {
        std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      }
    }

    void testGetBlockHeight() {
      // Data we are sending to the server.
      ::geyser::GetBlockHeightRequest request;

      // Container for the data we expect from the server.
      ::geyser::GetBlockHeightResponse reply;

      // Context for the client. It could be used to convey extra information to
      // the server and/or tweak certain RPC behaviors.
      ClientContext context;

      // The actual RPC.
      Status status = stub_->GetBlockHeight(&context, request, &reply);

      // Act upon its status.
      if (status.ok()) {
        std::cout << "block_height=" << reply.block_height() << std::endl;
      } else {
        std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      }
    }

    void testGetLatestBlockhash() {
      // Data we are sending to the server.
      ::geyser::GetLatestBlockhashRequest request;

      // Container for the data we expect from the server.
      ::geyser::GetLatestBlockhashResponse reply;

      {
        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->GetLatestBlockhash(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
          std::cout << "slot=" << reply.slot() << std::endl
                    << "hash=" << reply.blockhash() << std::endl
                    << "height=" << reply.last_valid_block_height() << std::endl;
        } else {
          std::cout << status.error_code() << ": " << status.error_message() << std::endl;
        }
      }

      {
        // Data we are sending to the server.
        ::geyser::IsBlockhashValidRequest request2;
        request2.set_blockhash( reply.blockhash() );

        // Container for the data we expect from the server.
        ::geyser::IsBlockhashValidResponse reply2;

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->IsBlockhashValid(&context, request2, &reply2);

        // Act upon its status.
        if (status.ok()) {
          std::cout << "valid=" << reply2.valid() << std::endl;
        } else {
          std::cout << status.error_code() << ": " << status.error_message() << std::endl;
        }
      }
    }

    void testSubscribe() {
      // Data we are sending to the server.
      ::geyser::SubscribeRequest request;

      // Container for the data we expect from the server.
      ::geyser::SubscribeUpdate update;

      // Context for the client. It could be used to convey extra information to
      // the server and/or tweak certain RPC behaviors.
      ClientContext context;

      // The actual RPC.
      auto rpc(stub_->Subscribe(&context));
      rpc->Write(request);

      for( unsigned cnt = 0; cnt < 10; ) {
        if( rpc->Read(&update) ) {
          std::cout << "*" << std::endl;
          ++cnt;
        }
      }

      rpc->WritesDone();
      rpc->Finish();
    }

  private:
    std::unique_ptr<geyser::Geyser::Stub> stub_;
};

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  std::string target_str = absl::GetFlag(FLAGS_target);
  // We indicate that the channel isn't authenticated (use of
  // InsecureChannelCredentials()).
  GeyserClient geyser(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));

  geyser.testGetVersion();
  geyser.testPing();
  geyser.testGetSlot();
  geyser.testGetBlockHeight();
  geyser.testGetLatestBlockhash();
  geyser.testSubscribe();

  return 0;
}

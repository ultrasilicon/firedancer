#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "geyser.grpc.pb.h"

ABSL_FLAG(std::string, target, "localhost:8123", "Server address");

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

  return 0;
}

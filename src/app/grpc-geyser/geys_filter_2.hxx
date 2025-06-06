struct GeyserSubscribeReactor : public ::grpc::ServerBidiReactor<::geyser::SubscribeRequest, ::geyser::SubscribeUpdate> {
  GeyserSubscribeReactor(GeyserServiceImpl * serv, geys_filter_t * filter) : serv_(serv), filter_(filter) {
    StartRead(&request_);
  }
  void OnReadDone(bool ok) override {
    if (ok) {
      geys_filter_add_sub(filter_, &request_, this);
      StartRead(&request_);
    } else {
      Finish(::grpc::Status::OK);
    }
  }
  void OnDone() override {
    geys_filter_un_sub(filter_, this);
    delete this;
  }
  GeyserServiceImpl * serv_;
  geys_filter_t * filter_;
  ::geyser::SubscribeRequest request_;
};

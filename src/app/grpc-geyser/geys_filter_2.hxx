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
    } else {
      Finish(::grpc::Status::OK);
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

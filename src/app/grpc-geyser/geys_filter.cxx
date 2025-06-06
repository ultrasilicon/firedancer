extern "C" {
#include "geys_filter.h"
}

#include "geyser.grpc.pb.h"
#include "geys_methods.hxx"
#include "geys_filter_2.hxx"

#include <vector>

class CompiledFilter {
  public:
    static CompiledFilter * compile(::geyser::SubscribeRequest * request) {
      return new CompiledFilter();
    }

    bool filterAccount(fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz) {
      return true;
    }
};

struct geys_filter {
    struct Elem {
        CompiledFilter * filter_;
        GeyserSubscribeReactor * reactor_;
    };
    std::vector<Elem> elems_;
};

geys_filter_t *
geys_filter_create() {
  return new geys_filter();
}

void
geys_filter_add_sub(geys_filter_t * filter, /* SubscribeRequest*/ void * request, GeyserSubscribeReactor_t * reactor) {
  filter->elems_.push_back( {
      CompiledFilter::compile( (::geyser::SubscribeRequest *) request),
      reactor
    } );
}

void
geys_filter_un_sub(geys_filter_t * filter, GeyserSubscribeReactor_t * reactor) {
  for( auto i = filter->elems_.begin(); i != filter->elems_.end(); ) {
    if( i->reactor_ == reactor )
      i = filter->elems_.erase(i);
    else
      ++i;
  }
}

void
geys_filter_acct(geys_filter_t * filter, ulong slot, fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz) {
  for( auto& i : filter->elems_ ) {
    if( i.filter_->filterAccount(key, meta, val, val_sz) ) {

      ::geyser::SubscribeUpdateAccount acct;
      ::geyser::SubscribeUpdate update;
      update.set_allocated_account(&acct);
      acct.set_slot(slot);
      acct.set_is_startup(false);
      ::geyser::SubscribeUpdateAccountInfo info;
      acct.set_allocated_account(&info);
      info.set_pubkey(key->uc, 32U);
      info.set_lamports(meta->info.lamports);
      info.set_owner(meta->info.owner, 32U);
      info.set_executable(meta->info.executable);
      info.set_data(val, val_sz);

      i.reactor_->StartWrite( &update );

      std::cout << "sent update\n";
    }
  }
}

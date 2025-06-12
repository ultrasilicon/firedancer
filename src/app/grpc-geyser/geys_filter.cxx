#include <mutex>
#include <vector>

#include "geyser.grpc.pb.h"
#include "geys_methods.hxx"
#include "geys_filter_2.hxx"

extern "C" {
#include "geys_filter.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/base58/fd_base58.h"
}

struct CompiledFilterAccount {
    std::string name_;
    std::vector<fd_hash_t> keys_;
    std::vector<fd_hash_t> owners_;
};

class CompiledFilter {
  public:
    static CompiledFilter * compile(::geyser::SubscribeRequest * request) {
      CompiledFilter * filt = new CompiledFilter();
      if( filt->compile_internal(request) )
        return filt;
      delete filt;
      return NULL;
    }

    bool filterAccount(fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz);

  private:
    bool compile_internal(::geyser::SubscribeRequest * request);

    std::vector<std::unique_ptr<CompiledFilterAccount>> accts_;
};

bool
CompiledFilter::compile_internal(::geyser::SubscribeRequest * request) {
  for( auto& i : request->accounts() ) {
    auto* a = new CompiledFilterAccount();
    a->name_ = i.first;
    auto& f = i.second;
    for( int j = 0; j < f.account_size(); ++j ) {
      auto& s = f.account(j);
      fd_hash_t hash;
      if( !fd_base58_decode_32( s.c_str(), hash.uc ) ) return false;
      a->keys_.push_back(hash);
    }
    for( int j = 0; j < f.owner_size(); ++j ) {
      auto& s = f.owner(j);
      fd_hash_t hash;
      if( !fd_base58_decode_32( s.c_str(), hash.uc ) ) return false;
      a->owners_.push_back(hash);
    }
    accts_.push_back(std::unique_ptr<CompiledFilterAccount>(a));
  }

  return true;
}

bool
CompiledFilter::filterAccount(fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz) {
  for( auto& f : accts_ ) {
    for( auto& h : f->keys_ ) {
      if( !memcmp( h.uc, key->uc, 32 ) ) return true;
    }
    for( auto& h : f->owners_ ) {
      if( !memcmp( h.uc, meta->info.owner, 32 ) ) return true;
    }
  }
  return false;
}

struct geys_filter {
    struct Elem {
        CompiledFilter * filter_;
        GeyserSubscribeReactor * reactor_;
    };
    std::vector<Elem> elems_;
    fd_spad_t * spad_;
    fd_funk_t * funk_;
    GeyserServiceImpl * serv_;

    geys_filter(fd_spad_t * spad, fd_funk_t * funk) : spad_(spad), funk_(funk) { }
    void filter_acct(ulong slot, fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz);
};

geys_filter_t *
geys_filter_create(fd_spad_t * spad, fd_funk_t * funk) {
  return new geys_filter(spad, funk);
}

void
geys_filter_set_service(geys_filter_t * filter, /* GeyserServiceImpl */ void *  serv) {
  filter->serv_ = (GeyserServiceImpl *)serv;
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
geys_filter::filter_acct(ulong slot, fd_pubkey_t * key, fd_account_meta_t * meta, const uchar * val, ulong val_sz) {
  for( auto& i : elems_ ) {
    if( i.filter_->filterAccount(key, meta, val, val_sz) ) {

      auto* update = new ::geyser::SubscribeUpdate();
      auto* acct = new ::geyser::SubscribeUpdateAccount();
      update->set_allocated_account(acct);
      acct->set_slot(slot);
      acct->set_is_startup(false);
      auto* info = new ::geyser::SubscribeUpdateAccountInfo();
      acct->set_allocated_account(info);
      info->set_pubkey(key->uc, 32U);
      info->set_lamports(meta->info.lamports);
      info->set_owner(meta->info.owner, 32U);
      info->set_executable(meta->info.executable);
      info->set_data(val, val_sz);

      i.reactor_->Update( update );
    }
  }
}

void
geys_filter_notify(geys_filter_t * filter, fd_replay_notif_msg_t * msg, uchar * blk_data, ulong blk_sz) {
  filter->serv_->notify(msg);

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( filter->funk_ );
  fd_funk_txn_xid_t xid;
  xid.ul[0] = xid.ul[1] = msg->slot_exec.slot;
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );

  ulong blockoff = 0;
  while (blockoff < blk_sz) {
    if ( blockoff + sizeof(ulong) > blk_sz )
      return;
    ulong mcount = *(const ulong *)(blk_data + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blk_sz )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)blk_data + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar txn_out[FD_TXN_MAX_SZ];
        ulong pay_sz = 0;
        const uchar* raw = (const uchar *)blk_data + blockoff;
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blk_sz - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
          FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu", txn_idx, mblk ) );
        }
        fd_txn_t * txn = (fd_txn_t *)txn_out;

        // geys_fd_txn_callback( fd, txn );

        /* Loop across signatures */
        // fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
        // for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
          // geys_fd_txn_sig_callback( fd, txn, (const uchar*)&sigs[j] );
        // }

        /* Loop across accoounts */
        fd_pubkey_t * accs = (fd_pubkey_t *)((uchar *)raw + txn->acct_addr_off);
        for( int i = 0UL; i < txn->acct_addr_cnt; i++ ) {
          bool writable = ((i < txn->signature_cnt - txn->readonly_signed_cnt) ||
                           ((i >= txn->signature_cnt) && (i < txn->acct_addr_cnt - txn->readonly_unsigned_cnt)));
          if( !writable ) continue;

          fd_spad_push(filter->spad_);

          fd_funk_rec_key_t recid = fd_funk_acc_key(&accs[i]);
          ulong val_sz;
          const uchar * val = (const uchar *) fd_funk_rec_query_copy( filter->funk_, funk_txn, &recid, fd_spad_virtual(filter->spad_), &val_sz );
          if( val ) {
            filter->filter_acct(msg->slot_exec.slot, &accs[i], (fd_account_meta_t *)val, val + sizeof(fd_account_meta_t), val_sz - sizeof(fd_account_meta_t));
          }

          fd_spad_pop(filter->spad_);
        }

        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != blk_sz )
    FD_LOG_ERR(("garbage at end of block"));
}

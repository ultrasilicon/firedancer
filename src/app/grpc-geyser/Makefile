all : geyser.pb.cxx solana-storage.pb.cxx

%.pb.cxx : %.proto
	/data/asiegel/pkg/bin/protoc -I/data/asiegel/pkg -I. --cpp_out=. --experimental_allow_proto3_optional $<
	mv $(subst .pb.cxx,.pb.cc,$@) $@

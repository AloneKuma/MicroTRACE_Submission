package receiver

import "google.golang.org/protobuf/proto"

var deterministicOpts = proto.MarshalOptions{Deterministic: true}

func deterministicMarshal(m proto.Message) ([]byte, error) { return deterministicOpts.Marshal(m) }

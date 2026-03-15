#!/usr/bin/env bash

# This script compiles available proto files inside the proto directories
# and place the generated cc and h files in the pb directories.
set -euo pipefail

PROTO_DIR=${PROTO_DIR:-fuzzer/proto}
PB_DIR=${PB_DIR:-fuzzer/pb}

protoc -I $PROTO_DIR --cpp_out=$PB_DIR/. $(find $PROTO_DIR -name "*.proto")

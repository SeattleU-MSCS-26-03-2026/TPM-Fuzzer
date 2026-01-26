#!/usr/bin/env bash
# Builds the TPM Reference code. Produces the Libraries provided
# in the source code alongside the Simulator Binary.
#
# NOTE: This requires clang++ & openssl to be present. As this currently
# builds the program with libFuzzer flags that are not present in gcc.

# - Exit on error
# - Treats unset variables as an error
# - Propagate any pipeline errors
set -euo pipefail

TPM_SRC=${TPM_SRC:-external/TPM}
INSTALL_DIR=${INSTALL_DIR:-external/TPM_install}

# Clone repository if not present
if [ ! -d "$TPM_SRC" ]; then
  git clone https://github.com/TrustedComputingGroup/TPM.git "$TPM_SRC"
  
  # Apply determinism patch if it exists
  PATCH_FILE="patches/determinism.patch"
  if [ -f "$PATCH_FILE" ]; then
    pushd "$TPM_SRC" >/dev/null
    git apply "../../$PATCH_FILE" && \
      echo "Determinism patch applied successfully" || \
      (echo "Failed to apply patch" && exit 1)
    popd >/dev/null
  else
    echo "No determinism patch found at $PATCH_FILE"
  fi
fi

# Fuzz/coverage compile flags for objects (no libFuzzer runtime)
SIM_CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined -fsanitize-coverage=trace-pc-guard"
SIM_LDFLAGS="-fsanitize=address,undefined"

build_domain() {
  local domain_src="$1" # relative to repo root
  local build_dir="$2"  # e.g. build_core

  echo "=== Configuring domain: src=$domain_src build=$build_dir ==="

  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  pushd "$build_dir" >/dev/null

  cmake -S "../$domain_src" -B . \
    -G Ninja \
    -D CMAKE_INSTALL_PREFIX="../$INSTALL_DIR" \
    -D CMAKE_BUILD_TYPE=Debug \
    -D CMAKE_C_COMPILER="$CC" \
    -D CMAKE_CXX_COMPILER="$CXX" \
    -D CMAKE_CXX_FLAGS="$SIM_CFLAGS" \
    -D CMAKE_EXE_LINKER_FLAGS="$SIM_LDFLAGS"

  cmake --build . --target install -j"$(nprocs)"

  popd >/dev/null
}

# Core Library
build_domain "$TPM_SRC/TPMCmd" "build_core"

# Platform (consumes core from install prefix)
build_domain "$TPM_SRC/TPMCmd/Platform" "build_platform"

# Simulator (consumes core+platform from install prefix)
build_domain "$TPM_SRC/TPMCmd/Simulator" "build_simulator"

echo "All domains built & installed to $INSTALL_DIR"

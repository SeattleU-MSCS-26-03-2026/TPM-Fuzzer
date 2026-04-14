{
  pkgs ? import <nixpkgs> { },
}:

pkgs.clangStdenv.mkDerivation {
  name = "tpm-fuzzer-shell";

  nativeBuildInputs = with pkgs; [
    llvmPackages_20.clang
    llvmPackages_20.clang-tools
    llvmPackages_20.libcxx
    llvmPackages_20.libclang
    llvmPackages_20.libcxxClang
    llvmPackages_20.bintools

    abseil-cpp
    autoconf
    automake
    binutils
    black
    cmake
    libtool
    libtpms
    ninja
    openssl_3
    pkg-config
    protobuf
    python3
    ty
    tpm2-tss
    uv
    xz
    zlib
  ];

  shellHook = ''
    export PS1="\n\[\033[1;32m\][\u@tpm-fuzzer:\w]\$\[\033[0m\] "
    export PROJECT_DIR="$PWD"
    export BUILD_DIR="$PWD/build"
    export FUZZER_BIN="$PWD/build/proto-fuzzer"

    export GEN_COVERAGE="1"
    export RUN_CORPUS_DIR="/tmp/corpus"
    export CORPUS_DIR="$PWD/proto-corpus"
    export SEEDS_DIR="$PWD/proto-seeds"
    export COVERAGE_DIR="$PWD/proto-coverage"
    export FUZZER_EXTRA_ARGS="-seed=38912891 -runs=10000"

    export CC=clang
    export CXX=clang++
  '';
}

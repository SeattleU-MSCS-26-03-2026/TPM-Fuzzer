{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  # Build tools and libraries
  nativeBuildInputs = with pkgs; [
    llvmPackages_20.clang
    llvmPackages_20.clang-tools
    llvmPackages_20.libcxx
    llvmPackages_20.libclang
    llvmPackages_20.libcxxClang
    llvmPackages_20.bintools
    autoconf
    automake
    binutils
    cmake
    ninja
    pkg-config
  ];

  # header, .pc files to propagate
  buildInputs = with pkgs; [
    abseil-cpp
    openssl_3
    tpm2-tss
    libtpms
    xz
    zlib
  ];

  # Developer tools
  packages = with pkgs; [
    black
    libtool
    protobuf
    python3
    ty
    uv
  ];

  shellHook = ''
    export CC=clang
    export CXX=clang++
    export PROJECT_DIR="$PWD"

    alias build="rm -rf build/ && cmake -B build -G Ninja && cmake --build build"
    alias run-proto="./scripts/run-fuzzer.sh"
    alias test="./scripts/test-seed.sh"
    # The '()' is a subshell; avoids changing directory if the command fails.
    alias sync="(cd $PROJECT_DIR/tools/seed-generation && uv run main.py --output-dir=$PROJECT_DIR/seeds --test-script=$PROJECT_DIR/scripts/test-seed.sh -recreate && rm NVChip default.profraw)"

    if [ -f $PROJECT_DIR/config/determinism.patch ]; then
      cd vendor/TPM && \
      patch -t -p1 -i $PROJECT_DIR/config/determinism.patch && \
      cd -
    fi
  '';
}

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
    export LOCAL_RUN="Y"

    alias build="rm -rf $PROJECT_DIR/build && cmake -B $PROJECT_DIR/build -G Ninja && cmake --build $PROJECT_DIR/build"
    alias run="$PROJECT_DIR/scripts/run-fuzzer.sh"
    alias test="$PROJECT_DIR/scripts/test-seed.sh"
    alias sync="(cd $PROJECT_DIR/tools/seed-generation && uv run main.py --output-dir=$PROJECT_DIR/seeds --test-script=$PROJECT_DIR/scripts/test-seed.sh -recreate && rm NVChip default.profraw)"
    alias track-coverage="$PROJECT_DIR/scripts/track-coverage"

    if [ -f $PROJECT_DIR/config/determinism.patch ]; then
      (cd $PROJECT_DIR/vendor/TPM && patch -t -p1 -i $PROJECT_DIR/config/determinism.patch)
    fi

    echo "TPM 2.0 Fuzzer
    Available commands:
      build          Rebuild the project, including Protobuf and binaries
      run            Run the fuzz targets
      test           Test a seed against the fuzzer
      sync           Ensure generated seeds are up to date
      track-coverage Track coverage"
  '';
}

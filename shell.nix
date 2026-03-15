{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  packages = with pkgs; [
    abseil-cpp
    autoconf
    binutils
    black
    clang
    cmake
    libclang
    libtool
    ninja
    openssl_3
    pkg-config
    protobuf
    python3
    ty
    uv
    xz
    zlib
  ];
}

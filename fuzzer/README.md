# Fuzzer

This directory contains the source code for the TPM Fuzzer binary. The fuzzer
uses libFuzzer to exercise the TPM SendCommand API and uncover unexpected
behavior.

## Developer Guide

Note: This project requires OpenSSL version 1.1.x through 3.5.x. It will not
build with OpenSSL 3.6 or newer. If your operating system includes a newer
version, you must direct CMake to a compatible OpenSSL installation.

To configure the build with your chosen OpenSSL version, provide the following
variables when running CMake:

```sh
cmake -B build -DOPENSSL_ROOT_DIR=<path to openssl root> -DOPENSSL_INCLUDE_DIR=<path to openssl root>/include
cmake --build build
```

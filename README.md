# TPM 2.0 Fuzzer
[![CI](https://github.com/seattleu-projectcenter/SUSE-26-03-Google/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/seattleu-projectcenter/SUSE-26-03-Google/actions/workflows/ci.yml)

## Overview

This repository contains a fuzzing harness for testing TPM 2.0 compliant implementations. It also provides a sample harness for the
[TCG TPM 2.0 Reference Implementation](https://github.com/TrustedComputingGroup/TPM). The fuzzing harness utilizes the [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
coverage-guided fuzzing engine.

The core harness library has the following dependencies:

- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator): Structure-aware mutator for libFuzzer
- [Clang](https://clang.llvm.org/) >= 12.0.0
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

## Usage

The provided TPM fuzz targets can be run using:

```sh
./scripts/run-fuzzer.sh --bin <fuzzer i.e. proto-fuzzer, Fuzzer>
```

You can also directly build and run the specific Docker containers:

```sh
docker compose build proto-fuzzer
docker compose build Fuzzer

docker compose run proto-fuzzer
ls -l
drwxr-xr-x 2 user users    4096 Apr  2 22:52 proto-artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 proto-corpus
drwxr-xr-x 3 user users   4096 Apr 13 18:10 proto-coverage
drwxr-xr-x 2 user users   4096 Mar 29 21:00 proto-seeds

docker compose run Fuzzer
ls -l
drwxr-xr-x 2 user users   4096 Apr 13 17:55 artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 corpus
drwxr-xr-x 3 user users   4096 Apr  2 22:54 coverage
drwxr-xr-x 2 user users   4096 Apr 13 21:27 seeds
```

### Custom TPM Implementation

The provided fuzz targets can be used to test your own custom TPM implementation. All you need to do is provide an implementation of the [wrapper functions](./include/harness/tpm_wrapper.h).

A minimal working example can be found in [./example](./example). Once the implementation has been configured and a library for it has been created, you can link any of the fuzz targets to your implementation to utilize them.

```cmake
add_executable(Fuzzer)

target_sources(Fuzzer
  PRIVATE
    src/fuzzer.cc
)
target_link_libraries(Fuzzer
  PRIVATE
    <Your Implementation>
)

target_compile_options(Fuzzer
  PRIVATE
    -g
    -fsanitize=fuzzer,address,signed-integer-overflow
    -fprofile-instr-generate
    -fcoverage-mapping
)

target_link_options(Fuzzer
  PRIVATE
    -fsanitize=fuzzer,address,signed-integer-overflow
    -fprofile-instr-generate
    -fcoverage-mapping
)
```

## Developer Documentation

Developer documentation and tips can be found [here](./DEVELOPER.md).

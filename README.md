# TPM 2.0 Fuzzer
[![CI](https://github.com/seattleu-projectcenter/SUSE-26-03-Google/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/seattleu-projectcenter/SUSE-26-03-Google/actions/workflows/ci.yml)

## Overview

This repository contains a fuzzing harness for testing TPM 2.0 compliant implementations. It also provides a sample harness for the
[TCG TPM 2.0 Reference Implementation](https://github.com/TrustedComputingGroup/TPM). The fuzzing harness utilizes the [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
coverage-guided fuzzing engine.

The framework supports both:

- **Byte-level fuzzing**: traditional mutation of raw byte inputs to explore low-level parsing and error handling paths
- **Structure-aware fuzzing**: generation and mutation of well-formed TPM command structures using protobuf to exercise deeper semantic logic and command-level behavior

The core harness library has the following dependencies:

- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator): Structure-aware mutator for libFuzzer
- [Clang](https://clang.llvm.org/) >= 12.0.0
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

## Fuzzing Background

If you're new to fuzz testing, the following resources provide a helpful introduction:

- [Why Fuzz?](https://github.com/google/fuzzing/blob/master/docs/why-fuzz.md)
- [Introduction to Fuzzing](https://github.com/google/fuzzing/blob/master/docs/intro-to-fuzzing.md)

## Usage

The provided TPM fuzz targets can be run using:

```sh
./scripts/run-fuzzer.sh --bin <fuzzer-type i.e. proto-fuzzer, fuzzer>
```

You can also directly build and run the specific Docker containers:

```sh
docker compose build proto-fuzzer
docker compose build fuzzer

docker compose run proto-fuzzer
ls -l
drwxr-xr-x 2 user users    4096 Apr  2 22:52 proto-artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 proto-corpus
drwxr-xr-x 3 user users   4096 Apr 13 18:10 proto-coverage
drwxr-xr-x 2 user users   4096 Mar 29 21:00 proto-seeds

docker compose run fuzzer
ls -l
drwxr-xr-x 2 user users   4096 Apr 13 17:55 artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 corpus
drwxr-xr-x 3 user users   4096 Apr  2 22:54 coverage
drwxr-xr-x 2 user users   4096 Apr 13 21:27 seeds
```

## Documentation
- [Our Architecture](./docs/ARCHITECTURE.md)
- [Developer Guide](./docs/DEVELOPER.md)
- [Seed Corpus](./docs/SEEDS.md)
- [Custom TPM Implementation](./docs/CUSTOM_TPM.md)

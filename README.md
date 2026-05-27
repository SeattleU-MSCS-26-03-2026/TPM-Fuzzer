# TPM 2.0 Fuzzer
[![CI](https://github.com/SeattleU-MSCS-26-03-2026/TPM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/SeattleU-MSCS-26-03-2026/TPM-Fuzzer/actions/workflows/ci.yml)

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


## Setup

This repository uses Git submodules for external dependencies, including the TCG TPM reference implementation and libprotobuf-mutator.

After cloning the repository, initialize and update the submodules:

```sh
git submodule update --init --recursive
```

If you already cloned the repository without submodules, run the same command from the repository root before building Docker images, applying patches, or running the fuzzers.

For more details, see the [Developer Guide](./docs/DEVELOPER.md).

## Usage

The provided TPM fuzz targets can be run using:

```sh
./scripts/run-fuzzer.sh -bin <fuzzer-type i.e. proto-fuzzer, fuzzer>
```

Common runner overrides:

```sh
./scripts/run-fuzzer.sh -bin fuzzer -maxRuns 1000
./scripts/run-fuzzer.sh -bin proto-fuzzer -maxTime 60
```

You can also directly build and run the specific Docker containers:

By default, the Docker Compose services use a fixed libFuzzer seed and a
default run limit. The byte-level fuzzer defaults to `100000` runs, while the
structure-aware fuzzer default is set in `docker-compose.yml`. These limits can
be overridden through the wrapper script with `-maxRuns` / `-maxTime`, or
directly with Docker Compose environment overrides.

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
- [Future Work](./docs/FUTURE_WORK.md)

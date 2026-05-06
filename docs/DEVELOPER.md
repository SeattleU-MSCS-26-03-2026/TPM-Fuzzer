# Developer Guide

This guide provides instructions for running, debugging, and extending the TPM fuzzing framework.

## Running the TPM fuzzer

The current setup runs the fuzzer against the [TCG TPM 2.0 Reference Implementation](https://github.com/TrustedComputingGroup/TPM), which serves as the default target for fuzzing. Other TPM implementations can be tested by providing a custom wrapper (see below).

### Script

``` sh
$ ./scripts/run-fuzzer.sh -bin <fuzzer i.e. proto-fuzzer, fuzzer>
```

#### Example: Byte-level fuzzing

``` sh
$ ./scripts/run-fuzzer.sh -bin fuzzer
$ ls -l

drwxr-xr-x 2 user users   4096 Apr 13 17:55 artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 corpus
drwxr-xr-x 3 user users   4096 Apr  2 22:54 coverage
drwxr-xr-x 2 user users   4096 Apr 13 21:27 seeds
# Open Coverage in browser
$ open coverage/index.html
```

#### Example: Structure-aware fuzzing

``` sh
$ ./scripts/run-fuzzer.sh -bin proto-fuzzer
$ ls -l

drwxr-xr-x 2 user users   4096 Apr  2 22:52 proto-artifacts
drwxr-xr-x 2 user users   4096 Apr 13 18:10 proto-corpus
drwxr-xr-x 3 user users   4096 Apr 13 18:10 proto-coverage
drwxr-xr-x 2 user users   4096 Mar 29 21:00 proto-seeds
# Open Coverage in browser
$ open proto-coverage/index.html
```

### Docker Compose

The helper script runs the Docker Compose services using the default libFuzzer arguments configured in `docker-compose.yml`. By default, both fuzzers run with:

```sh
-seed=38912891 -runs=100000
```

this makes fuzzing runs more reproducible by using a fixed libFuzzer seed and limits each run to 100,000 executions.

You can change these defaults in docker-compose.yml, or override them when running a service:

```sh
# build the docker compose images
$ docker compose build

# run with environment overrides
docker compose run --rm -e FUZZER_EXTRA_ARGS="-seed=1234 -runs=1000" fuzzer
```

Any valid libFuzzer argument can be added here, such as:

```sh
-max_len=4096
-timeout=10
-artifact_prefix=/srv/artifacts/
```
more can be found [here](https://llvm.org/docs/LibFuzzer.html#options)

## Seed Corpus

The seed corpus contains initial inputs used by the fuzzer to explore TPM command execution paths.

Seeds are critical for:
- reaching valid execution paths
- guiding mutation toward meaningful inputs
- improving overall coverage

### Location

Seed files are organized into initial inputs and runtime-generated corpus data:

**Initial seeds (checked into the repository):**
- `seeds/` – initial inputs used to bootstrap byte-level fuzzing
- `proto-seeds/` – initial structure-aware seeds (protobuf-based)

**Generated corpus (produced during fuzzing):**
- `corpus/` – runtime-generated inputs for byte-level fuzzing
- `proto-corpus/` – runtime-generated inputs for structure-aware fuzzing

Generated corpus files may be included when available to improve coverage and provide additional starting points for future fuzzing runs.

### More Information

For detailed information on seed structure, examples, and seed generation scripts, see: [Seed Guide](./SEEDS.md)

## Using a Custom TPM Implementation

By default, the fuzzer runs against the [TCG TPM 2.0 Reference Implementation](https://github.com/TrustedComputingGroup/TPM).

The framework supports integrating custom TPM implementations through a wrapper interface. This allows you to reuse the existing fuzzing infrastructure with your own TPM backend.

At a high level, this involves:
- implementing the wrapper functions defined in `include/harness/tpm_wrapper.h`
- linking your implementation with the fuzzing targets

For detailed instructions, see: [Custom TPM Integration Guide](./CUSTOM_TPM.md)

## Running the unit tests

Unit tests should be run through Docker so the test environment matches the fuzzer build environment.

```sh
# use this command to run available unit tests
$ docker compose run --rm test

# then shut down all containers
$ docker compose down
```
## Tracking coverage

Coverage is generated automatically when the fuzzer runs inside Docker. The generated HTML report is written to the mounted coverage directory.

``` sh
./scripts/run-fuzzer.sh -bin fuzzer -track
```

The `-track` flag currently tracks coverage progression for the byte-level fuzzer only. It reads the latest coverage summary and appends a new row to `coverage-history/history.csv`.

```sh
# View coverage history
$ ls coverage-history/
-rw-r--r-- 1 fuzzer users 1008K Feb 11 17:27 coverage-2025-11-28T05:08:09Z-96db8ae.tar.gz
-rw-r--r-- 1 fuzzer users 1008K Feb 11 17:27 coverage-2026-01-14T05:08:09Z-b8f630f.tar.gz
-rw-r--r-- 1 fuzzer users  974K Feb 11 17:27 coverage-2026-01-28T05:08:09Z-4efc310.tar.gz
-rw-r--r-- 1 fuzzer users   460 Feb 11 17:27 history.csv
```

### Breakdown of report headers

LLVM Coverage Reports typically have the following headers:
  - **Regions**: Total number of instrumented code regions (fine-grained source ranges mapped to coverage counters)
  - **Missed Regions**: Number of instrumented regions never executed
  - **Regions Cover %**: Percentage of regions executed at least once
  - **Functions**: Total number of instrumented functions
  - **Missed Functions**: Number of functions never entered
  - **Functions Cover %**: Percentage of functions executed at least once
  - **Lines**: Total number of executable source lines
  - **Missed Lines**: Number of executable lines never executed
  - **Lines Cover %**: Percentage of executable lines executed at least once
  - **Branches**: Total number of control-flow branches (true/false edges, switch cases, etc.)
  - **Missed Branches**: Number of branch paths never taken
  - **Branches Cover %**: Percentage of branch paths executed at least once

## Testing TPM commands against the fuzzer

This project provides a testing binary that can be used to test TPM2.0 Commands against the configured byte-level fuzzer.


### Script

``` sh
$ ./script/test-seed.sh seeds/TPM_SEED
```

### Example

```sh
$ ./script/test-seed.sh seeds/TPMGetRandom-variant0-202601241713

Size of OBJECT = 2104
Size of components in TPMT_SENSITIVE = 1384
    TPMI_ALG_PUBLIC                 2
    TPM2B_AUTH                      50
    TPM2B_DIGEST                    50
    TPMU_SENSITIVE_COMPOSITE        1282
==============================
            REQUEST           
==============================
TPM Command Tag (hex): 0x8001
TPM Command Length (hex): 0x0000000c
TPM Command Buffer Size (bytes): 12
TPM Command Code (hex): 0x0000017b
TPM Command (hex):
80 01 00 00 00 0c 00 00 01 7b 00 30 
TPM Command (binary):
10000000 00000001 00000000 00000000 00000000 00001100 00000000 00000000 
00000001 01111011 00000000 00110000 


==============================
            RESPONSE          
==============================
TPM Response Tag (hex): 0x8001
TPM Response Size (hex): 0x0000003c
TPM Response Buffer Size (bytes): 60
TPM Response Code: 0x00000000
```

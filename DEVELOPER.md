# Developer Guide
## Running the TPM fuzzer

### Script

``` sh
$ ./scripts/run-fuzzer.sh
$ ls -l

drwxr-xr-x 2 fuzzer users  20480 Jan 24 14:08 corpus
drwxr-xr-x 3 fuzzer users   4096 Jan 24 14:04 coverage
# Open Coverage in browser
$ xdg-open coverage/index.html
```

### Docker Compose

```sh
# build the docker compose images
$ docker compose build

# use this command to start fuzzing TPM send command
$ docker compose run --rm fuzzer

# run with environment overrides
$ docker compose run -e MAX_RUNS=100000000000 --rm fuzzer
```

## Running the unit tests

```sh
# use this command to run available unit tests
$ docker compose run --rm test

# then shut down all containers
$ docker compose down
```
## Tracking coverage

``` sh
$ ./scripts/run-fuzzer.sh --track
$ ls -l

drwxr-xr-x 2 fuzzer users  20480 Jan 24 14:08 corpus/
drwxr-xr-x 3 fuzzer users   4096 Jan 24 14:04 coverage/
drwxr-xr-x 3 fuzzer users   4096 Jan 24 14:04 coverage-history/

# View coverage history
$ ls coverage-history/
-rw-r--r-- 1 fuzzer users 1008K Feb 11 17:27 coverage-2025-11-28T05:08:09Z-96db8ae.tar.gz
-rw-r--r-- 1 fuzzer users 1008K Feb 11 17:27 coverage-2026-01-14T05:08:09Z-b8f630f.tar.gz
-rw-r--r-- 1 fuzzer users  974K Feb 11 17:27 coverage-2026-01-28T05:08:09Z-4efc310.tar.gz
-rw-r--r-- 1 fuzzer users   460 Feb 11 17:27 history.csv

# Open Coverage in browser
$ xdg-open coverage/index.html
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

This project provides a testing binary that can be used to test TPM2.0 Commands against
the configured fuzzer.

Usage:

``` sh
$ ./build/Tester seeds/TPM_SEED
```

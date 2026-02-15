# SUSE 26.03 Google

## Developer Guide
### Running the TPM fuzzer

#### Script

``` sh
$ ./scripts/run-fuzzer.sh
$ ls -l

drwxr-xr-x 2 fuzzer users  20480 Jan 24 14:08 corpus
drwxr-xr-x 3 fuzzer users   4096 Jan 24 14:04 coverage
# Open Coverage in browser
$ xdg-open coverage/index.html
```

#### Docker Compose

```sh
# build the docker compose images
$ docker compose build

# use this command to start fuzzing TPM send command
$ docker compose run --rm fuzzer

# run with environment overrides
$ docker compose run -e MAX_RUNS=100000000000 --rm fuzzer
```

### Running the unit tests

```sh
# use this command to run available unit tests
$ docker compose run --rm test

# then shut down all containers
$ docker compose down
```
### Tracking coverage

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

#### Breakdown of report headers

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

### Running the TPM simulator

The TPM Simulator can be run using [Docker](https://docs.docker.com/). We provide a Dockerfile (`Dockerfile.simulator`) which you can use to build and start the simulator from [this repository](https://github.com/TrustedComputingGroup/TPM/tree/main). This simulator is helpful for testing and developing applications that interact with the TPM 2.0 API without needing a physical TPM device.

#### Steps:

```sh
# 1. Build the Docker image
$ docker build -t suse-26-03 .

# 2. Run the simulator container in detached mode
$ docker container run -d suse-26-03

# 3. List all running containers
$ docker container ls
CONTAINER ID   IMAGE        COMMAND   CREATED        STATUS        PORTS   NAMES
d3f941e9909d   suse-26-03   "…"       ... minutes ago   Up ... minutes         intelligent_gates

# 4. View simulator logs
$ docker container logs -f intelligent_gates
```

#### Interact with TPM simulator from another container

```sh
$ docker compose run --rm tools
# now we are in the other container and you can put in commands to interact with TPM simulator
# check the available commands here https://tpm2-tools.readthedocs.io/en/latest/
# example
/app# tpm2_startup -c
/app# tpm2_readclock
...

# at the end you can exit the container with exit
/app# exit

# then shut down all containers
$ docker compose down
```

### Testing TPM commands against the fuzzer

This project provides a testing binary that can be used to test TPM2.0 Commands against
the configured fuzzer.

Usage:

``` sh
$ ./build/Tester seeds/TPM_SEED
```

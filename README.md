# SUSE 26.03 Google

## Developer Guide
### Running the TPM Simulator

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

### Running with Docker Compose

```sh
# 1. Run all available containers using docker compose
$ docker compose up -d

# 2. View simulator logs
$ docker container logs -f intelligent_gates

# 3. Shut all containers down
$ docker compose down
```

### Interact with TPM simulator from another container

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

### Run TPM Fuzzer

```sh
# use this command to start fuzzing TPM send command
$ docker compose run --rm fuzzer

# then shut down all containers
$ docker compose down
```

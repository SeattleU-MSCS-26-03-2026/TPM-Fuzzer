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
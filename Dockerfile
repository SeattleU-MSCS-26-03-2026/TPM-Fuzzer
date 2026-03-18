FROM debian:stable AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV CXX=clang++
ENV CC=clang

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    protobuf-compiler \
    libabsl-dev \
    libprotobuf-dev \
    binutils \
    liblzma-dev \
    libz-dev \
    pkg-config \
    autoconf \
    libtool \
    openssl \
    patch \
    libssl-dev \
    libclang-rt-dev \
    clang \
    llvm \
    cmake \
    ninja-build && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY . /srv/

RUN mkdir -p /srv/artifacts /srv/seeds /srv/corpus /srv/corpus-running

# Apply determinism patch to TPM submodule
RUN if [ -f config/determinism.patch ]; then \
      cd /srv/vendor/TPM && \
      patch -p1 -i /srv/config/determinism.patch && \
      echo "Determinism patch applied successfully" || \
      (echo "Failed to apply patch" && exit 1); \
    else \
      echo "No determinism patch found"; \
    fi

FROM base AS fuzzer

RUN cmake -B /srv/build -G Ninja -S /srv
RUN cmake --build /srv/build

CMD ["/srv/scripts/docker/start-fuzzer.sh"]

FROM base AS test

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    catch2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cmake -B /srv/build -G Ninja -S /srv -DRUN_UNIT_TESTS=ON
RUN cmake --build /srv/build

CMD ["ctest", "--test-dir", "/srv/build", "--verbose"]

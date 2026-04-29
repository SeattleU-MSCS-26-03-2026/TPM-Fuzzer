FROM debian:stable AS base

ARG UID=1000
ARG GID=1000
ARG USERNAME=dev

ENV DEBIAN_FRONTEND=noninteractive
ENV CXX=clang++
ENV CC=clang
ENV HOME=/home/${USERNAME}
ENV XDG_CACHE_HOME=/home/${USERNAME}/.cache

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
    libtss2-dev \
    cmake \
    ninja-build && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid ${GID} ${USERNAME} && \
    useradd --uid ${UID} --gid ${GID} --create-home --home-dir ${HOME} --shell /bin/bash ${USERNAME} && \
    mkdir -p /srv/artifacts /srv/seeds /srv/corpus /srv/corpus-running ${XDG_CACHE_HOME} && \
    chown -R ${UID}:${GID} /srv ${HOME}

WORKDIR /srv
COPY --chown=${UID}:${GID} . /srv/

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
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

USER ${USERNAME}

RUN cmake -B /srv/build -G Ninja -S /srv
RUN cmake --build /srv/build

CMD ["/srv/scripts/docker/start-fuzzer.sh"]

FROM base AS test

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    catch2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER ${USERNAME}

RUN cmake -B /srv/build -G Ninja -S /srv -DRUN_UNIT_TESTS=ON
RUN cmake --build /srv/build

CMD ["ctest", "--test-dir", "/srv/build", "--verbose"]

#!/usr/bin/env bash

# This script regenerates the initial seed test cases for the
# TPM using [the seed generator](tools/seed-generation)

main() {
    [ -d seeds ] || mkdir -p seeds

    docker compose run --build --rm \
        -v "$(pwd)/seeds:/seeds" \
        -w /srv/tools/seed-generation \
        fuzzer \
        uv run main.py --output-dir=/seeds "$@"
    exit 0
}

main "$@"

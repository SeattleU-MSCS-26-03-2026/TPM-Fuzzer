#!/usr/bin/env bash

# This script builds and runs the fuzzer Docker environment.
# It:
#   - Ensures required directories (corpus, coverage) exist.
#   - Verifies those directories are not owned by root.
#   - Accepts an optional first argument as FUZZER_MAX_RUNS, which is passed
#     into the fuzzer container as an environment variable.

main() {
    [ -d corpus ] || mkdir corpus
    [ -d coverage ] || mkdir coverage

    if [ -O corpus ] || [ -O coverage ]; then
        :
    else
        echo "Warning: 'corpus' or 'coverage' directory is owned by root. Please adjust permissions, e.g.:"
        echo "  sudo chown -R \$(whoami):\$(whoami) corpus coverage"
        exit 1
    fi

    BLUE="\033[34m"
    RESET="\033[0m"

    max_runs="$1"

    echo -e "${BLUE}[1/3] Destroying pre-existing image.${RESET}\n"
    docker compose down --rmi=all &>/dev/null

    echo -e "${BLUE}[2/3] Building the fuzzer image.${RESET}\n"
    docker compose build fuzzer &>/dev/null

    echo -e "${BLUE}[3/3] Running Fuzzer...${RESET}\n\n"
    if [ -n "$max_runs" ]; then
        echo -e "${BLUE}[INFO] Max Runs: $max_runs${RESET}\n"
        docker compose run -e FUZZER_MAX_RUNS="$max_runs" --rm fuzzer
    else
        docker compose run --rm fuzzer
    fi

    echo -e "${BLUE}[INFO] Destroying containers.${RESET}\n"
    docker compose down --rmi=all --remove-orphans
}

main "$@"

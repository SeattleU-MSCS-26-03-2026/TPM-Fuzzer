#!/usr/bin/env bash

# This script builds and runs the fuzzer Docker environment.
# It:
#   - Ensures required directories (corpus, coverage) exist.
#   - Verifies those directories are not owned by root.
#
# Options:
#   -track:   Track coverage information.
#   -bin BIN: Choose which fuzzer to run (fuzzer or proto-fuzzer).
#   -combine: Merge profdata from both fuzzers and generate a combined
#              coverage report in coverage-overall/. At least one fuzzer
#              must have been run first.
#   -maxRuns N: Override libFuzzer -runs for this invocation.
#   -maxTime N: Override libFuzzer -max_total_time for this invocation.
# Notes:
#   Compose provides default FUZZER_SEED / FUZZER_MAX_RUNS values.
#   -maxRuns and -maxTime override those defaults for the current invocation.
#   FUZZER_EXTRA_ARGS remains available for advanced direct Docker Compose use.

# --------------------------------------------------------------------
# Environment flags
# --------------------------------------------------------------------
FUZZER_BIN="${FUZZER_BIN:-Fuzzer}"
LOCAL_RUN="${LOCAL_RUN:-N}"

# --------------------------------------------------------------------
# Miscellaneous
# --------------------------------------------------------------------
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
BLUE="\033[34m"
RESET="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"

# Append summarized coverage data into a CSV history file.
track_coverage() {
    "${SCRIPT_DIR}"/track-coverage "$1"
}

combine_coverage() {
    if [[ ! -f coverage/bytearray/fuzzer.profdata && ! -f coverage/proto/fuzzer.profdata ]]; then
        echo -e "${RED}[ERROR] No fuzzer profdata found. Run at least one fuzzer first.${RESET}"
        echo -e "${CYAN} Expected: coverage/bytearray/fuzzer.profdata or coverage/proto/fuzzer.profdata"
        exit 1
    fi

    mkdir -p coverage/overall

    echo -e "${BLUE}[1/1] Generating combined coverage report.${RESET}\n"
    docker compose run --rm \
        --volume "$(pwd)/coverage/bytearray:/srv/coverage/bytearray" \
        --volume "$(pwd)/coverage/proto:/srv/coverage/proto" \
        --volume "$(pwd)/coverage/overall:/srv/coverage/overall" \
        --entrypoint /srv/scripts/docker/combine-coverage.sh \
        fuzzer

    echo -e "${CYAN}[INFO] Combined coverage report written to coverage/overall/${RESET}\n"
}

ensure_directories() {
    [ -d corpus ] || mkdir -p corpus/bytearray && mkdir -p corpus/proto
    [ -d coverage ] || mkdir -p coverage/bytearray && mkdir -p coverage/proto
    [ -d artifacts ] || mkdir -p artifacts/bytearray && mkdir -p artifacts/proto

    if [ -O corpus ] && [ -O coverage ] && [ -O artifacts ]; then
        :
    else
        echo -e "${YELLOW}[WARNING] one or more required directories are owned by root or another user. Please adjust permissions, e.g.:"
        echo -e "  sudo chown -R \$(whoami):\$(whoami) corpus coverage artifacts"
        echo -ne "${RESET}"
        exit 1
    fi
}

main() {
    local track=0
    local combine=0
    local max_runs=""
    local max_time=""
    local bin="$(echo "${FUZZER_BIN}" | tr '[:upper:]' '[:lower:]')"
    local bin_explicit=0

    if [[ $# -eq 0 ]]; then
        echo -e "${BLUE}Usage:${RESET} ${1} [-track] [-bin <name>] [-combine] [-maxRuns <n>] [-maxTime <seconds>]"
        echo -e "${CYAN}Options:${RESET}"
        echo "    -track: Track coverage metrics to coverage-history/"
        echo "    -bin: Select fuzzer binary to run i.e proto-fuzzer, Fuzzer"
        echo "    -combine: Merge coverage reports"
        echo "    -maxRuns: Override libFuzzer -runs"
        echo "    -maxTime: Override libFuzzer -max_total_time"
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
        -track)
            track=1
            shift
            ;;
        -local)
            LOCAL_RUN="Y"
            shift
            ;;
        -bin)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "${RED}[ERROR] -bin requires a value.${RESET}"
                exit 1
            fi
            bin="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
            bin_explicit=1
            shift
            ;;
        -combine)
            combine=1
            shift
            ;;
        -maxRuns)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "${RED}[ERROR] -maxRuns requires a value.${RESET}"
                exit 1
            fi
            max_runs="$1"
            shift
            ;;
        -maxTime)
            shift
            if [[ $# -eq 0 ]]; then
                echo -e "${RED}[ERROR] -maxTime requires a value.${RESET}"
                exit 1
            fi
            max_time="$1"
            shift
            ;;
        --*)
            echo -e "${RED}[ERROR] Unsupported option '$1'. Use single-dash options like -bin or -track.${RESET}"
            exit 1
            ;;
        *)
            shift
            ;;
        esac
    done

    # -combine without -bin: skip the fuzzer run entirely
    if [[ $combine -eq 1 && $bin_explicit -eq 0 ]]; then
        combine_coverage
        return
    fi

    ensure_directories "${0}"

    if [[ "$LOCAL_RUN" = "N" ]]; then
        echo -e "${BLUE}[1/4] Destroying pre-existing images.${RESET}"
        docker compose down --rmi=all &>/dev/null

        echo -e "${BLUE}[2/4] Building the ${bin} image.${RESET}"
        docker compose build $bin &>/dev/null

        echo -e "${BLUE}[3/4] Running ${bin}...${RESET}\n"
        local -a run_env=()
        if [[ -n "$max_time" && -z "$max_runs" ]]; then
            run_env+=(-e "FUZZER_MAX_RUNS=")
        fi
        if [[ -n "$max_runs" ]]; then
            run_env+=(-e "FUZZER_MAX_RUNS=$max_runs")
        fi
        if [[ -n "$max_time" ]]; then
            run_env+=(-e "FUZZER_MAX_TIME=$max_time")
        fi
        docker compose run --rm "${run_env[@]}" $bin

        echo -e "${CYAN}[INFO] Destroying containers.${RESET}"
        docker compose down --rmi=all --remove-orphans
    else
        local bin_name="$bin"
        if [[ "$bin_name" = "fuzzer" ]]; then
            bin_name="Fuzzer"
        fi

        FUZZER_BIN_NAME="$bin_name" \
            FUZZER_MAX_RUNS="$max_runs" \
            FUZZER_MAX_TIME="$max_time" \
            "$SCRIPT_DIR"/docker/start-fuzzer.sh
    fi

    if [[ $track -eq 1 ]]; then
        echo -e "${BLUE}[4/4] Tracking Coverage.${RESET}"
        track_coverage "$bin"
    fi

    if [[ $combine -eq 1 ]]; then
        combine_coverage
    fi
}

main "$@"

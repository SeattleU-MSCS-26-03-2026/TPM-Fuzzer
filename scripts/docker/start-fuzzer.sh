#!/usr/bin/env bash
set -Eeuo pipefail
# This script starts the fuzzer in a Docker environment.
# It can also be run locally but requires llvm-cov and llvm-profdata.
# Configurations can be overridden through environment variables.
# Logs will provide details on progress and output [N/<MAX_RUNS>] information.
# Structured controls:
#   FUZZER_MAX_RUNS and FUZZER_MAX_TIME define the common limits.
# Advanced controls:
#   FUZZER_EXTRA_ARGS is appended after the structured flags for additional
#   libFuzzer options when running the service directly via Docker Compose.

# --------------------------------------------------------------------
# Environment flags
# --------------------------------------------------------------------
# Chosen to work well in a container where /srv is the project root.
PROJECT_DIR="${PROJECT_DIR:-/srv}"
FUZZER="${FUZZER_BIN_NAME:-proto-fuzzer}"
CORPUS_DIR="${CORPUS_DIR:-$PROJECT_DIR/corpus}"
RUN_CORPUS_DIR="${RUN_CORPUS_DIR:-$PROJECT_DIR/corpus-running}"
SEEDS_TYPE="${SEEDS_TYPE:-bytearray}"
SEEDS_DIR="${SEEDS_DIR:-$PROJECT_DIR/seeds/$SEED_TYPE}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$PROJECT_DIR/artifacts}"
GEN_COVERAGE="${GEN_COVERAGE:-0}"
FUZZER_EXTRA_ARGS="${FUZZER_EXTRA_ARGS:-}"
FUZZER_MAX_RUNS="${FUZZER_MAX_RUNS:-}"
FUZZER_MAX_TIME="${FUZZER_MAX_TIME:-}"

# --------------------------------------------------------------------
# Variables
# --------------------------------------------------------------------
BUILD_DIR="$PROJECT_DIR/build"
FUZZER_BIN="${FUZZER_BIN:-$BUILD_DIR/$FUZZER}"
TPM_SOURCE_DIR="$PROJECT_DIR/vendor/TPM"
FUZZER_SOURCE_DIR="$PROJECT_DIR/src"
COVERAGE_DIR="${COVERAGE_DIR:-$BUILD_DIR/coverage}"
SRC_COVERAGE_DIR="${SRC_COVERAGE_DIR:-$BUILD_DIR/src-coverage}"
LLVM_PROFRAW="$COVERAGE_DIR/fuzzer.profraw"
LLVM_PROFDATA="$COVERAGE_DIR/fuzzer.profdata"

# --------------------------------------------------------------------
# Miscellaneous
# --------------------------------------------------------------------
BLUE="\033[34m"
RESET="\033[0m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"

log() {
    local prefix
    local tag="$1"
    local msg="$2"

    case "$tag" in
    info)
        prefix="${CYAN}[INFO] "
        ;;
    warning)
        prefix="${YELLOW}[WARNING] "
        ;;
    error)
        prefix="${RED}[ERROR] "
        ;;
    step)
        prefix="\n${BLUE}[STEP] "
        ;;
    *)
        prefix=""
        ;;
    esac

    echo -e "${prefix}${msg}${RESET}"
}

require_bin() {
    if [[ ! -x "$1" ]]; then
        log error "Required executable not found: $1"
        exit 1
    fi
}

generate_coverage() {
    require_bin "$(command -v llvm-profdata)"
    require_bin "$(command -v llvm-cov)"

    log step "Creating profdata"
    llvm-profdata merge --sparse "$LLVM_PROFRAW" -o "$LLVM_PROFDATA"

    mapfile -t tpm_sources < <(
        find "$TPM_SOURCE_DIR" -type f \( -name '*.c' -o -name '*.cc' \)
    )

    mapfile -t fuzzer_sources < <(
        find "$FUZZER_SOURCE_DIR" -type f \( -name '*.cc' \)
    )

    log step "Generating TPM coverage HTML"
    llvm-cov show "$FUZZER_BIN" \
        -instr-profile="$LLVM_PROFDATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$COVERAGE_DIR" \
        "${tpm_sources[@]}"

    log step "Generating TPM coverage summary"
    llvm-cov report "$FUZZER_BIN" \
        -instr-profile="$LLVM_PROFDATA" \
        "${tpm_sources[@]}" >"$COVERAGE_DIR/report.txt"

    log step "Generating fuzzer-source coverage HTML"
    llvm-cov show "$FUZZER_BIN" \
        -instr-profile="$LLVM_PROFDATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$SRC_COVERAGE_DIR" \
        "${fuzzer_sources[@]}"
}

main() {
    require_bin "$FUZZER_BIN"
    mkdir -p "$CORPUS_DIR" "$RUN_CORPUS_DIR" "$SEEDS_DIR" "$ARTIFACTS_DIR" "$COVERAGE_DIR"

    local -a fuzzer_args=()
    if [[ -n "$FUZZER_MAX_RUNS" ]]; then
        fuzzer_args+=("-runs=$FUZZER_MAX_RUNS")
    fi
    if [[ -n "$FUZZER_MAX_TIME" ]]; then
        fuzzer_args+=("-max_total_time=$FUZZER_MAX_TIME")
    fi
    if [[ -n "$FUZZER_EXTRA_ARGS" ]]; then
        # split extra args into individual libFuzzer args.
        read -r -a extra_args_array <<<"$FUZZER_EXTRA_ARGS"
        fuzzer_args+=("${extra_args_array[@]}")
    fi

    log info "Using fuzzer args: ${fuzzer_args[*]}"

    log step "Starting fuzzer"
    LLVM_PROFILE_FILE="$LLVM_PROFRAW" \
        "$FUZZER_BIN" \
        -artifact_prefix="$ARTIFACTS_DIR/" \
        "${fuzzer_args[@]}" \
        "$RUN_CORPUS_DIR" \
        "$CORPUS_DIR" \
        "$SEEDS_DIR"

    log step "Merging corpus"
    "$FUZZER_BIN" \
        -merge=1 \
        "${fuzzer_args[@]}" \
        "$CORPUS_DIR" \
        "$RUN_CORPUS_DIR"

    if [[ "$GEN_COVERAGE" == "1" ]]; then
        mkdir -p "$COVERAGE_DIR" "$SRC_COVERAGE_DIR"
        log step "Generating coverage"
        generate_coverage
    fi

    log step "Done"
}

main "$@"

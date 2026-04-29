#!/usr/bin/env bash
# This script starts the fuzzer in a Docker environment.
# It can also be run locally but requires llvm-cov and llvm-profdata.
# Configurations can be overridden through environment variables.
# Logs will provide details on progress and output [N/<MAX_RUNS>] information.
set -Eeuo pipefail

# Defaults are chosen to work well in a container where /srv is the project root.
PROJECT_DIR="${PROJECT_DIR:-/srv}"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build}"
FUZZER_BIN_NAME="${FUZZER_BIN_NAME:-proto-fuzzer}"
FUZZER_BIN="${FUZZER_BIN:-$BUILD_DIR/$FUZZER_BIN_NAME}"

CORPUS_DIR="${CORPUS_DIR:-$PROJECT_DIR/corpus}"
RUN_CORPUS_DIR="${RUN_CORPUS_DIR:-$PROJECT_DIR/corpus-running}"
SEEDS_DIR="${SEEDS_DIR:-$PROJECT_DIR/seeds/bytearray}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$PROJECT_DIR/artifacts}"

GEN_COVERAGE="${GEN_COVERAGE:-0}"
FUZZER_EXTRA_ARGS="${FUZZER_EXTRA_ARGS:-}"

COVERAGE_DIR="${COVERAGE_DIR:-$BUILD_DIR/coverage}"
SRC_COVERAGE_DIR="${SRC_COVERAGE_DIR:-$BUILD_DIR/src-coverage}"
LLVM_PROFRAW="${LLVM_PROFRAW:-$COVERAGE_DIR/fuzzer.profraw}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$COVERAGE_DIR/fuzzer.profdata}"

TPM_SOURCE_DIR="${TPM_SOURCE_DIR:-$PROJECT_DIR/vendor/TPM}"
FUZZER_SOURCE_DIR="${FUZZER_SOURCE_DIR:-$PROJECT_DIR/src}"

log() {
    printf '[INFO] %s\n' "$*"
}

require_bin() {
    if [[ ! -x "$1" ]]; then
        printf '[ERROR] Required executable not found: %s\n' "$1" >&2
        exit 1
    fi
}

generate_coverage() {
    require_bin "$(command -v llvm-profdata)"
    require_bin "$(command -v llvm-cov)"

    log "Creating profdata"
    llvm-profdata merge --sparse "$LLVM_PROFRAW" -o "$LLVM_PROFDATA"

    mapfile -t tpm_sources < <(
        find "$TPM_SOURCE_DIR" -type f \( -name '*.c' -o -name '*.cc' \)
    )

    mapfile -t fuzzer_sources < <(
        find "$FUZZER_SOURCE_DIR" -type f \( -name '*.cc' \)
    )

    log "Generating TPM coverage HTML"
    llvm-cov show "$FUZZER_BIN" \
        -instr-profile="$LLVM_PROFDATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$COVERAGE_DIR" \
        "${tpm_sources[@]}"

    log "Generating TPM coverage summary"
    llvm-cov report "$FUZZER_BIN" \
        -instr-profile="$LLVM_PROFDATA" \
        "${tpm_sources[@]}" >"$COVERAGE_DIR/report.txt"

    log "Generating fuzzer-source coverage HTML"
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

    log "Starting fuzzer"
    LLVM_PROFILE_FILE="$LLVM_PROFRAW" \
        "$FUZZER_BIN" \
        -artifact_prefix="$ARTIFACTS_DIR/" \
        $FUZZER_EXTRA_ARGS \
        "$RUN_CORPUS_DIR" \
        "$CORPUS_DIR" \
        "$SEEDS_DIR"

    log "Merging corpus"
    "$FUZZER_BIN" \
        -merge=1 \
        $FUZZER_EXTRA_ARGS \
        "$CORPUS_DIR" \
        "$RUN_CORPUS_DIR"

    if [[ "$GEN_COVERAGE" == "1" ]]; then
        mkdir -p "$COVERAGE_DIR" "$SRC_COVERAGE_DIR"
        log "Generating coverage"
        generate_coverage
    fi

    log "Done"
}

main "$@"

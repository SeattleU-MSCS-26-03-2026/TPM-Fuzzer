#!/usr/bin/env bash
# Runs inside the fuzzer container (coverage-overall service).
# Merges profdata from the byte fuzzer and proto fuzzer and generates
# a unified coverage report in /srv/coverage-overall/.
set -Eeuo pipefail

BYTE_PROFDATA="${BYTE_PROFDATA:-/srv/coverage/fuzzer.profdata}"
PROTO_PROFDATA="${PROTO_PROFDATA:-/srv/proto-coverage/fuzzer.profdata}"
OUTPUT_DIR="${OUTPUT_DIR:-/srv/coverage-overall}"
COMBINED_PROFDATA="$OUTPUT_DIR/combined.profdata"

BYTE_FUZZER_BIN="${BYTE_FUZZER_BIN:-/srv/build/Fuzzer}"
PROTO_FUZZER_BIN="${PROTO_FUZZER_BIN:-/srv/build/proto-fuzzer}"

TPM_SOURCE_DIR="${TPM_SOURCE_DIR:-/srv/vendor/TPM}"
FUZZER_SOURCE_DIR="${FUZZER_SOURCE_DIR:-/srv/src}"

log() {
    printf '[INFO] %s\n' "$*"
}

main() {
    local -a profdata_inputs=()
    local primary_bin=""
    local -a extra_objects=()

    if [[ -f "$BYTE_PROFDATA" ]]; then
        profdata_inputs+=("$BYTE_PROFDATA")
        if [[ -z "$primary_bin" ]]; then
            primary_bin="$BYTE_FUZZER_BIN"
        else
            extra_objects+=(-object "$BYTE_FUZZER_BIN")
        fi
        log "Using byte fuzzer profdata: $BYTE_PROFDATA"
    else
        log "Warning: byte fuzzer profdata not found ($BYTE_PROFDATA), skipping"
    fi

    if [[ -f "$PROTO_PROFDATA" ]]; then
        profdata_inputs+=("$PROTO_PROFDATA")
        if [[ -z "$primary_bin" ]]; then
            primary_bin="$PROTO_FUZZER_BIN"
        else
            extra_objects+=(-object "$PROTO_FUZZER_BIN")
        fi
        log "Using proto fuzzer profdata: $PROTO_PROFDATA"
    else
        log "Warning: proto fuzzer profdata not found ($PROTO_PROFDATA), skipping"
    fi

    if [[ ${#profdata_inputs[@]} -eq 0 ]]; then
        printf '[ERROR] No profdata files found. Run at least one fuzzer first.\n' >&2
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    log "Merging profdata from ${#profdata_inputs[@]} source(s)"
    llvm-profdata merge --sparse "${profdata_inputs[@]}" -o "$COMBINED_PROFDATA"

    mapfile -t tpm_sources < <(
        find "$TPM_SOURCE_DIR" -type f \( -name '*.c' -o -name '*.cc' \)
    )

    log "Generating combined coverage HTML"
    llvm-cov show "$primary_bin" \
        "${extra_objects[@]}" \
        -instr-profile="$COMBINED_PROFDATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$OUTPUT_DIR" \
        "${tpm_sources[@]}"

    log "Generating combined coverage summary"
    llvm-cov report "$primary_bin" \
        "${extra_objects[@]}" \
        -instr-profile="$COMBINED_PROFDATA" \
        "${tpm_sources[@]}" >"$OUTPUT_DIR/report.txt"

    log "Done. Combined coverage report written to $OUTPUT_DIR"
}

main "$@"

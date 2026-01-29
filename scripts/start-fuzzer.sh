#!/usr/bin/env bash
set -e

# This script starts the fuzzer in a Docker environment.
# It can also be run locally but requires llvm-cov and llvm-profdata.
# Configurations can be overridden through environment variables.
# Logs will provide details on progress and output [N/<MAX_RUNS>] information.

# ----------------------------------
# LLVM Coverage Configuration
# ----------------------------------
PROFILE_FILE=${LLVM_PROF_FILE:-'/srv/build/Fuzzer.profraw'}
PROFILE_DATA=${LLVM_PROF_DATA:-'/srv/build/Fuzzer.profdata'}
COVERAGE_OUTPUT_DIR=${FUZZER_COVERAGE_OUT_DIR:-'/srv/build/coverage'}
SRC_COVERAGE_OUTPUT_DIR=${FUZZER_SRC_COVERAGE_OUT_DIR:-'/srv/build/src-coverage'}

# ----------------------------------
# Fuzzer Configurations
# ----------------------------------
GENERATED_CORPUS_DIRECTORY=${GEN_CORPUS_DIR:-'/srv/corpus'}
SEED_CORPUS_LIST=${SEED_CORPUS_DIR:-'/srv/seeds'}
MAX_RUNS=${FUZZER_MAX_RUNS:-100000}
FUZZER_EXTRA_ARGS=${FUZZER_EXTRA_ARGS:-''}

main() {
    echo "Starting fuzzer... [1/3]"
    LLVM_PROFILE_FILE=$PROFILE_FILE ./build/Fuzzer -runs="$MAX_RUNS" "$FUZZER_EXTRA_ARGS" "$GENERATED_CORPUS_DIRECTORY" "$SEED_CORPUS_LIST"

    echo "Creating coverage report... [2/3]"
    llvm-profdata merge -sparse "$PROFILE_FILE" -o "$PROFILE_DATA"

    echo "Generating coverage output... [3/4]"
    llvm-cov show /srv/build/Fuzzer \
        -instr-profile="$PROFILE_DATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$COVERAGE_OUTPUT_DIR" \
        $(find /srv/fuzzer/vendor/TPM -type f \( -name '*.c' -o -name '*.cc' \))

    echo "Generating coverage report for Fuzzer source code... [4/4]"
    llvm-cov show /srv/build/Fuzzer \
        -instr-profile="$PROFILE_DATA" \
        -format=html \
        -coverage-watermark=70,5 \
        -output-dir="$SRC_COVERAGE_OUTPUT_DIR" \
        $(find /srv/fuzzer/ -type f \( -name '*.cc' \))

    echo "Fuzzer execution completed successfully!"
}

main "@"

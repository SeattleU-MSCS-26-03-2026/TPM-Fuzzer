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

# NOTE: First directory is where the final corpus is stored
GENERATED_CORPUS_DIRECTORY=${GEN_CORPUS_DIR:-'/srv/corpus'}
SEED_CORPUS_LIST=${SEED_CORPUS_DIR:-'/srv/seeds'}
FUZZER_EXTRA_ARGS=${FUZZER_EXTRA_ARGS:-''}
GEN_COVERAGE=${FUZZER_GEN_COVERAGE:-0}
MERGE_DIRECTORY=${FUZZER_MERGE_DIRECTORY:-/srv/corpus-running}
FUZZER_ARTIFACT_PATH=${FUZZER_ARTIFACT_PATH:-/srv/artifacts/}

main() {
    local steps=6

    if [[ $GEN_COVERAGE -eq 0 ]]; then
        steps=2
    fi

    echo "[INFO] Ensuring required directories exist..."
    mkdir -p $GENERATED_CORPUS_DIRECTORY $MERGE_DIRECTORY $FUZZER_ARTIFACT_PATH

    echo "Starting fuzzer... [1/$steps]"
    LLVM_PROFILE_FILE=$PROFILE_FILE ./build/Fuzzer -artifact_prefix="$FUZZER_ARTIFACT_PATH" $FUZZER_EXTRA_ARGS "$MERGE_DIRECTORY" "$GENERATED_CORPUS_DIRECTORY" "$SEED_CORPUS_LIST"
    echo ""

    echo "Merging corpus... [2/$steps]"
    LLVM_PROFILE_FILE=$PROFILE_FILE ./build/Fuzzer -merge=1 $FUZZER_EXTRA_ARGS "$GENERATED_CORPUS_DIRECTORY" "$MERGE_DIRECTORY"
    echo ""

    if [[ $GEN_COVERAGE -ne 0 ]]; then
        echo "Creating coverage report... [3/$steps]"
        llvm-profdata merge -sparse "$PROFILE_FILE" -o "$PROFILE_DATA"

        echo "Generating coverage output... [4/$steps]"
        llvm-cov show /srv/build/Fuzzer \
            -instr-profile="$PROFILE_DATA" \
            -format=html \
            -coverage-watermark=70,5 \
            -output-dir="$COVERAGE_OUTPUT_DIR" \
            $(find /srv/vendor/TPM -type f \( -name '*.c' -o -name '*.cc' \))

        echo "Coverage Report... [5/$steps]"
        llvm-cov report /srv/build/Fuzzer \
            -instr-profile="$PROFILE_DATA" \
            $(find /srv/vendor/TPM -type f \( -name '*.c' -o -name '*.cc' \)) >"$COVERAGE_OUTPUT_DIR/report.txt"

        echo "Generating coverage report for Fuzzer source code... [6/$steps]"
        llvm-cov show /srv/build/Fuzzer \
            -instr-profile="$PROFILE_DATA" \
            -format=html \
            -coverage-watermark=70,5 \
            -output-dir="$SRC_COVERAGE_OUTPUT_DIR" \
            $(find /srv/src/ -type f \( -name '*.cc' \))
    fi

    echo "Fuzzer execution completed successfully!"
}

main "@"

#!/bin/env bash
set -e

generate_coverage() {
    echo "Creating coverage report..."
    llvm-profdata merge -sparse /srv/build/Fuzzer.profraw -o /srv/build/Fuzzer.profdata

    llvm-cov show /srv/build/Fuzzer \
        -instr-profile=/srv/build/Fuzzer.profdata \
        -format=html \
        -output-dir=/srv/build/coverage \
        $(find /srv/fuzzer/src /srv/fuzzer/vendor/TPM -type f \( -name '*.c' -o -name '*.cc' \))
    
    echo "Done!"
}

trap generate_coverage EXIT

echo "Running fuzzer..."
./build/Fuzzer /srv/corpus

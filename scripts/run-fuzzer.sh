#!/usr/bin/env bash

# This script builds and runs the fuzzer Docker environment.
# It:
#   - Ensures required directories (corpus, coverage) exist.
#   - Verifies those directories are not owned by root.
#
# Options:
#   --track: Track coverage information.
BLUE="\033[34m"
RESET="\033[0m"
COVERAGE_HISTORY="${FUZZER_COV_HISTORY:-coverage-history/history.csv}"
COVERAGE_REPORT="${FUZZER_COV_REPORT:-coverage/report.txt}"

# Append summarized coverage data into a CSV history file.
#
# This script:
#   - Reads a text coverage REPORT_TXT (from llvm-cov) that contains
#     a line beginning with "TOTAL" and coverage statistics.
#   - Extracts summary totals for regions, functions, lines, and branches,
#     along with their missed counts and coverage percentages.
#   - Appends a CSV row to coverage_history.csv containing:
#       * UTC timestamp
#       * Current Git commit short SHA (or "unknown" if not in a git repo)
#       * Coverage metrics for regions, functions, lines, and branches
track_coverage() {
    local report="$1"

    if [[ -z $report ]]; then
        echo "Usage: track-coverage <REPORT_TXT>"
        exit 1
    fi

    local timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

    if [ ! -f "$COVERAGE_HISTORY" ]; then
        cat >"$COVERAGE_HISTORY" <<'CSV'
Timestamp,GitSHA,Regions,Missed Regions,Regions Cover %,Functions,Missed Functions,Functions Cover %,Lines,Missed Lines,Lines Cover %,Branches,Missed Branches,Branches Cover %
CSV
    fi

    awk -v ts="$timestamp" -v sha="$sha" '
  $1=="TOTAL" {
    gsub(/%/,"",$4); gsub(/%/,"",$7); gsub(/%/,"",$10); gsub(/%/,"",$13);
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      ts,sha,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
  }
' "$report" >>"$COVERAGE_HISTORY"
    echo -e "${BLUE}[INFO] Appending to coverage history ($COVERAGE_HISTORY).${RESET}\n"
}

archive_coverage() {
    local coverage_directory="${1:-coverage/}"
    local timestamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
    local sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    local out="coverage-history/coverage-$timestamp-$sha.tar.gz"
    if [ ! -d "$coverage_directory" ]; then
        echo "Warning: $coverage_directory doesn't exist! Skipping archiving"
        exit 1
    fi

    echo -e "${BLUE}[INFO] Archiving coverage to $out.${RESET}\n"
    tar czf "$out" "$coverage_directory"
}

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

    local track=0
    local bin="${FUZZER_BIN,,}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
        --track)
            track=1
            shift
            ;;
        --bin)
            shift
            bin="${1,,}"
            ;;
        *)
            shift
            ;;
        esac
    done

    echo -e "${BLUE}[1/4] Destroying pre-existing image.${RESET}\n"
    docker compose down --rmi=all &>/dev/null

    echo -e "${BLUE}[2/4] Building the fuzzer image.${RESET}\n"
    docker compose build $bin &>/dev/null

    echo -e "${BLUE}[3/4] Running Fuzzer...${RESET}\n\n"
    docker compose run --rm $bin

    echo -e "${BLUE}[INFO] Destroying containers.${RESET}\n"
    docker compose down --rmi=all --remove-orphans

    if [[ $track -eq 1 ]]; then
        echo -e "${BLUE}[4/4] Tracking Coverage.${RESET}\n"
        track_coverage "$COVERAGE_REPORT"
        archive_coverage
    fi
}

main "$@"

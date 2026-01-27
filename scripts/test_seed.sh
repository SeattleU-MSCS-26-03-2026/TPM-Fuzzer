#!/usr/bin/env bash
#
#  Builds and runs the 'fuzzer' Docker service to execute the Tester
#  binary against a provided corpus file. Exits with an error if
#  no corpus file is supplied or if the file does not exist.

main() {
    local RED="\033[0;31m"
    local GREEN="\033[0;32m"
    local YELLOW="\033[1;33m"
    local BLUE="\033[0;34m"
    local CYAN="\033[0;36m"
    local RESET="\033[0m"

    [ -d corpus ] || mkdir corpus
    [ -d coverage ] || mkdir coverage

    if [ -O corpus ] || [ -O coverage ]; then
        :
    else
        echo "Warning: 'corpus' or 'coverage' directory is owned by root. Please adjust permissions, e.g.:"
        echo "  sudo chown -R \$(whoami):\$(whoami) corpus coverage"
        exit 1
    fi

    if [[ -z "$1" || ! -e "$1" ]]; then
        echo -e "${RED}Error:${RESET} corpus file is required and must exist."
        echo -e "${YELLOW}Usage:${RESET} $0 <corpus-file>"
        exit 1
    fi

    local corpus=$1

    echo -e "${CYAN}[*]${RESET} Using corpus file: ${BLUE}${corpus}${RESET}"
    echo -e "${CYAN}[*]${RESET} Building fuzzer Docker image..."
    docker compose build fuzzer &>/dev/null

    echo -e "${CYAN}[*]${RESET} Running fuzzer with provided corpus..."
    docker compose run --rm fuzzer ./build/Tester "$corpus"

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[+] Fuzzer run completed successfully.${RESET}"
    else
        echo -e "${RED}[-] Fuzzer run encountered an error.${RESET}"
    fi

    echo -e "${CYAN}[*]${RESET} Destroying containers."
    docker compose down --rmi=all --remove-orphans
}

main "$@"

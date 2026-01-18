#!/usr/bin/env python3

"""
This script generates seed files for the TPM (Trusted Platform Module) commands
to be used in fuzz testing. The seeds are defined by specified command
structures utilizing TPM constants.

The generated seed files are saved in a specified output directory. The script
can also recreate existing seed files based on user input.

Usage:
    python generate_seeds.py [options]

Options:
    --recreate: Recreate all existing seed files.
    --output-dir: Specify a different output directory for the seed files (default is "seeds/").

Resources:
    - TPM Specification: https://trustedcomputinggroup.org/resource/tpm-library-specification/
"""

from typing import List, Callable, Dict
import os
import argparse
import time

SeedFunction = Callable[[], List[bytes]]

DEFAULT_SEED_DIRECTORY = "seeds/"
BYTE_ORDER = "big"

# TPM Constants
TPM_ST_NULL = 0x8000
TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002
TPM_CC_GETRANDOM = 0x0000017B



TPM_CC_HASH = 0x0000017D

TPM_CC_CREATE = 0x00000153
TPM_ALG_SHA1   = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C

TPM_RH_OWNER    = 0x40000001
TPM_RH_NULL     = 0x40000007
TPM_RH_PLATFORM = 0x4000000C


def tpm_get_rand_seeds() -> List[bytes]:
    """
    Generates seeds for the TPM2_GetRandom Command. This
    function generates variants of the command based on
    collected interesting seeds from previous testing.

    Command Structure:
      [TPMI_ST_COMMAND_TAG(tag i.e TPM_ST_NO_SESSIONS)][UINT32(Command Size)]
      [TPM_CC(Command Code)][UINT16 (Bytes Requested Parameter)]
    """
    seeds: List[bytes] = []
    for st in [TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS]:
        for bytes_requested in [16, 32, 64, 0, 48]:
            # NOTE: Command Size is Total number of input bytes including
            #       tag and command size.
            command_size = 2 + 4 + 4 + 2
            seed = (
                st.to_bytes(2, byteorder=BYTE_ORDER) +
                command_size.to_bytes(4, byteorder=BYTE_ORDER) +
                TPM_CC_GETRANDOM.to_bytes(4, byteorder=BYTE_ORDER) +
                bytes_requested.to_bytes(2, byteorder=BYTE_ORDER)
            )
            seeds.append(seed)
    return seeds

def generate_seeds(directory: str, recreate: bool, seeds: Dict[str, SeedFunction]):
    """
    Generate seeds for all supported TPM Commands.

    Args:
        directory (str): Output directory for the generated seeds.
        recreate (bool): Flag to indicate whether to recreate existing seeds.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

    current_timestamp = time.strftime("%Y%m%d%H%M")

    for (cmd, func) in seeds.items():
        seed_files = [f for f in os.listdir(directory) if f.startswith(cmd)]

        if seed_files:
            for seed_file in seed_files:
                if recreate:
                    print(f"Deleting seed file: {seed_file}")
                    os.remove(os.path.join(directory, seed_file))
                else:
                    print(f"Skipping existing seed file: {seed_file}")

            if not recreate:
                continue

        seeds: List[bytes] = func()

        for (i, seed) in enumerate(seeds):
            filename = f"{cmd}-variant{i}-{current_timestamp}"
            filepath = os.path.join(directory, filename)
            with open(filepath, 'wb') as f:
                f.write(seed)
            print(f"Generated seed file: {filename}")
    return

def tpm_hash_seeds() -> List[bytes]:
    """
    Generates a small, representative seed corpus for the TPM2_Hash command.

    This mirrors the previous standalone script behavior by producing exactly
    three well-formed TPM2_Hash command blobs (WITHOUT the harness frame).
    The harness frame wrapper is applied by generate_seeds() via wrap_tpm_commands().

    Command Structure (unwrapped):
      [TPMI_ST_COMMAND_TAG][UINT32(commandSize)][TPM_CC_HASH]
      [TPM2B_MAX_BUFFER][hashAlg][hierarchy]
    """
    seeds: List[bytes] = []

    # Exactly the same 3 cases as your standalone script
    cases = [
        ("sha1-owner",           b"test hash data", TPM_ALG_SHA1,   TPM_RH_OWNER),
        ("sha256-platform",      b"another test",   TPM_ALG_SHA256, TPM_RH_PLATFORM),
        ("sha384-null-random",   b"random bytes",   TPM_ALG_SHA384, TPM_RH_NULL),
    ]

    st = TPM_ST_NO_SESSIONS  # Same as standalone script

    for _name, data, alg, hier in cases:
        # TPM2B_MAX_BUFFER: UINT16 size + bytes
        params = (
            len(data).to_bytes(2, byteorder=BYTE_ORDER) +
            data +
            alg.to_bytes(2, byteorder=BYTE_ORDER) +
            hier.to_bytes(4, byteorder=BYTE_ORDER)
        )

        # Header: tag(2) + commandSize(4) + commandCode(4)
        command_size = 2 + 4 + 4 + len(params)
        cmd = (
            st.to_bytes(2, byteorder=BYTE_ORDER) +
            command_size.to_bytes(4, byteorder=BYTE_ORDER) +
            TPM_CC_HASH.to_bytes(4, byteorder=BYTE_ORDER) +
            params
        )

        seeds.append(cmd)

    return seeds



if __name__ == "__main__":
    # NOTE: Update this to include a seed function
    seeds = {
        "TPMGetRandom": tpm_get_rand_seeds,
        "TPMHash": tpm_hash_seeds,
        "TPMCreate": tpm_create_seeds,
    }

    parser = argparse.ArgumentParser(description='Generates the seed corpus for the Fuzzer.')
    parser.add_argument('--recreate', action='store_true', help='Recreate all seeds.')
    parser.add_argument('--output-dir', default=DEFAULT_SEED_DIRECTORY, help='Override output directory for seeds.')
    args = parser.parse_args()

    generate_seeds(args.output_dir, args.recreate, seeds)

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
import subprocess

from typing import List, Callable, Dict, Optional
import os
import argparse
import time
import difflib
import re
from python_util import *

SeedFunction = Callable[[], List[bytes]]

DEFAULT_SEED_DIRECTORY = "seeds/"
BYTE_ORDER = "big"

# TPM Public Key identifiers for SPDM
TPM_PUB_KEY_TPM_SPDM_00 = 0x00000000

# The First HMAC Session is typically this.
# Subsequent ones should be around the same HMAC Session
# Handle Range
TPM_FIRST_HMAC_SESSION_HANDLE = 0x02000000


def tpm_incremental_self_test_seeds() -> List[bytes]:
    """
    Generates seeds for TPM2_IncrementalSelfTest.

    Command Structure:
        [TPM_ST_NO_SESSIONS][UINT32 commandSize]
        [TPM_CC_INCREMENTALSELFTEST][TPML_ALG toTest]

    TPML_ALG:
        [UINT32 count][TPM_ALG_ID * count]
    """
    seeds: list[bytes] = []
    # variants: empty list, one alg, two algs
    variants = [
        [],  # count=0
        [TPM_ALG.SHA256],  # count=1
        [TPM_ALG.SHA1, TPM_ALG.SHA256],  # count=2
    ]

    for algs in variants:
        seeds.append(bytes(TPMIncrementalSelfTest(algs)))

    return seeds


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
    test_cases = [16, 32, 64, 0, 48]
    for st in [TPM_ST.NO_SESSIONS, TPM_ST.SESSIONS]:
        for bytes_requested in test_cases:
            seeds.append(bytes(TPMGetRandom(bytes_requested, st)))
    return seeds


def tpm_get_capability_seeds() -> List[bytes]:
    """
    Generates seeds for the TPM2_GetCapability command.
    Query TPM for capabilities and properties.

    Command Structure:
      [TPMI_ST_COMMAND_TAG][UINT32(Command Size)][TPM_CC_GETCAPABILITY]
      [TPM_CAP(capability)][UINT32(property)][UINT32(propertyCount)]

    Parameters:
      - capability: Which type of capability to query (4 bytes)
      - property: Starting property value (4 bytes)
      - propertyCount: How many properties to return (4 bytes)
    """
    seeds: List[bytes] = []
    test_cases = [
        # TPM_CAP_HANDLES - All 7 valid handle types
        (TPM_CAP.HANDLES, 0x80000000, 10, "HT_TRANSIENT"),
        (TPM_CAP.HANDLES, 0x81000000, 10, "HT_PERSISTENT"),
        (TPM_CAP.HANDLES, 0x01000000, 10, "HT_NV_INDEX"),
        (TPM_CAP.HANDLES, 0x02000000, 10, "HT_LOADED_SESSION"),
        (TPM_CAP.HANDLES, 0x03000000, 10, "HT_SAVED_SESSION"),
        (TPM_CAP.HANDLES, 0x00000000, 10, "HT_PCR"),
        (TPM_CAP.HANDLES, 0x40000000, 10, "HT_PERMANENT"),
        # Minimal diversity to seed other switch cases (fuzzer explores from here)
        (TPM_CAP.ALGS, 0x0001, 10, "Algorithms"),
        (TPM_CAP.COMMANDS, 0x0000017A, 10, "Commands"),
        (TPM_CAP.PCRS, 0x00000000, 16, "PCRs"),
        (TPM_CAP.TPM_PROPERTIES, 0x00000100, 64, "TPM properties"),
        (TPM_CAP.ECC_CURVES, 0x0000, 10, "ECC curves"),
        # Special cases requiring specific values (fuzzer unlikely to find)
        (TPM_CAP.AUTH_POLICIES, 0x40000001, 10, "Auth policies - permanent handle"),
        (
            TPM_CAP.PUB_KEYS,
            TPM_PUB_KEY_TPM_SPDM_00,
            1,
            "SPDM key - exact value required",
        ),
        (TPM_CAP.ACT, 0x00000000, 1, "ACT - disabled feature, hits error path"),
    ]

    # Generate seeds with single tag type only - fuzzer mutates tag field easily
    for capability, property_val, property_count, _desc in test_cases:
        seeds.append(bytes(TPMGetCapability(capability, property_val, property_count)))

    return seeds


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
        ("sha1-owner", b"test hash data", TPM_ALG.SHA1, TPM_RH.OWNER),
        ("sha256-platform", b"another test", TPM_ALG.SHA256, TPM_RH.PLATFORM),
        ("sha384-null-random", b"random bytes", TPM_ALG.SHA384, TPM_RH.NULL),
    ]

    for _name, data, alg, hier in cases:
        seeds.append(bytes(TPMHash(data, alg, hier)))

    return seeds


def _create_variant(name: str, timestamp: str, directory: str, content: bytes, force: Optional[bool] = False):
    def request_section(input: str) -> str:
        pattern = (
            r"=+\n\s*REQUEST\s*\n=+\n"
            r"(.*?)"
            r"(?==+\n\s*RESPONSE\s*\n=+)"
           )

        match = re.search(pattern, input, re.DOTALL)
        if not match:
            print(f"Input: {input}")
            raise ValueError("REQUEST section not found")

        section = match.group(0)
        return section.rstrip()

    existing_items = [ p for p in os.listdir("seeds/") if p.startswith(f"{name}-") ]
    if len(existing_items) > 0:
        out = os.path.join(directory, existing_items[0]);
        with open(out, "rb") as f:
            data = f.read()

        if data != content and force:
            print(f"EXPECTED BYTES CHANGED: {name}\n")
            pwd = os.getcwd()
            actual = request_section(subprocess.run(
                [f"{pwd}/scripts/test_seed.sh", out],
                capture_output=True,
                text=True,
                check=True,
            ).stdout)

            current = os.path.join(directory, f"{name}-{timestamp}");
            with open(current, "wb") as f:
                f.write(content)

            expected = request_section(subprocess.run(
                [f"{pwd}/scripts/test_seed.sh", current],
                capture_output=True,
                text=True,
                check=True,
            ).stdout)

            diff = difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
            )

            changes = "".join(diff)
            if len(changes.strip()) > 0:
                print(f"{changes}\n")
            os.remove(out)
    else:
        out = os.path.join(directory, f"{name}-{timestamp}");
        with open(out, "wb") as f:
            f.write(content)
        print(f"Generated seed file: {out}")


def _run_commands(
    directory: str,
    cmd: str,
    command: SeedFunction | TPMCommand | List[List[TPMCommand]],
    timestamp: str,
    force: bool,
):

    if isinstance(command, TPMCommand):
        _create_variant(f"{cmd}-variant0", timestamp, directory, bytes(command), force)
    elif callable(command):
        seeds = command()
        for i, seed in enumerate(seeds):
             _create_variant(f"{cmd}-variant{i}", timestamp, directory, seed, force)
    elif isinstance(command, list):
        for i, sequence in enumerate(command):
            seed = b''
            for f in sequence:
                seed += bytes(f)
            _create_variant(f"{cmd}-variant{i}", timestamp, directory, seed, force)


def _generate_seeds(
    directory: str,
    recreate: bool,
    seeds: Dict[str, Union[SeedFunction | TPMCommand | List[List[TPMCommand]]]],
):
    """
    Generate seeds for all supported TPM Commands.

    Args:
        directory (str): Output directory for the generated seeds.
        recreate (bool): Flag to indicate whether to recreate existing seeds.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

    current_timestamp = time.strftime("%Y%m%d%H%M")

    for cmd, _cmd in seeds.items():
        seed_files = [f for f in os.listdir(directory) if f.startswith(cmd)]
        _run_commands(directory, cmd, _cmd, current_timestamp, force=recreate)


if __name__ == "__main__":
    # NOTE: Update this to include a seed function
    seeds = {
        "TPMGetRandom": tpm_get_rand_seeds,
        "TPMHash": tpm_hash_seeds,
        "TPMGetTestResult": TPMGetTestResult(),
        "TPMSelfTest": [[TPMSelfTest(TPMI_YES_NO.YES)], [TPMSelfTest(TPMI_YES_NO.NO)]],
        "TPMReadClock": TPMReadClock(),
        "TPMCreate": [
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA256, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA256, 1024),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA1, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA1, 1024),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA384, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA384, 1024),
            ],
        ],
        "TPMCreatePrimary": [
            [TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048), TPMGetRandom(16)],
            [TPMGetRandom(32), TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048)],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
            ],
        ],
        "TPMStartAuthSessionHMAC": [
            [TPMStartAuthSession(TPM_RH.NULL, TPM_RH.NULL, session_type=TPM_SE.HMAC)],
            [
                TPMStartAuthSession(TPM_RH.NULL, TPM_RH.NULL, session_type=TPM_SE.HMAC),
                TPMCreatePrimary(TPM_FIRST_HMAC_SESSION_HANDLE, TPM_ALG.SHA256, 2048),
            ],
        ],
        "TPMIncrementalSelfTest": tpm_incremental_self_test_seeds,
        "TPMGetCapability": tpm_get_capability_seeds,
    }

    parser = argparse.ArgumentParser(
        description="Generates the seed corpus for the Fuzzer."
    )
    parser.add_argument("--recreate", action="store_true", help="Recreate all seeds.")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_SEED_DIRECTORY,
        help="Override output directory for seeds.",
    )
    args = parser.parse_args()

    _generate_seeds(args.output_dir, args.recreate, seeds)

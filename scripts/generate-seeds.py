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
TPM_CC_STARTAUTHSESSION = 0x00000176
TPM_CC_CREATEPRIMARY = 0x00000131
TPM_CC_CREATE = 0x00000153
TPM_CC_HASH = 0x0000017D

TPM_RH_NULL = 0x40000007
TPM_RH_OWNER = 0x40000001
TPM_RH_PLATFORM = 0x4000000C

TPM_ALG_RSA = 0x0001
TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_NULL = 0x0010

TPM_SE_HMAC = 0x00
TPM_RS_PW = 0x40000009

PARENT_HANDLE = 0x81000001


def u16(x):
    return x.to_bytes(2, "big")


def u32(x):
    return x.to_bytes(4, "big")


def build_start_auth_session_cmd(session_handle_hint: int) -> bytes:
    """
    Build a TPM2_StartAuthSession command. The TPM will *return* a
    real session handle, but for fuzzing we only care about the command.
    This is a minimal, plausible HMAC session.
    """
    tag = TPM_ST_NO_SESSIONS
    cc = TPM_CC_STARTAUTHSESSION

    # TPM2_StartAuthSession parameters:
    # TPMI_DH_OBJECT tpmKey        (4 bytes)  – use TPM_RH_NULL
    # TPMI_DH_ENTITY bind          (4 bytes)  – use TPM_RH_NULL
    # TPM2B_NONCE nonceCaller      (2 + N)    – make empty (N=0)
    # TPM2B_ENCRYPTED_SECRET salt  (2 + N)    – empty
    # TPM_SE sessionType           (1 byte)   – HMAC
    # TPMT_SYM_DEF symmetric       (2 + 2 + 2) – alg, keyBits, mode (use ALG_NULL)
    # TPMI_ALG_HASH authHash       (2 bytes)  – SHA256

    tpm_key = TPM_RH_NULL.to_bytes(4, BYTE_ORDER)
    bind = TPM_RH_NULL.to_bytes(4, BYTE_ORDER)
    nonce = (0).to_bytes(2, BYTE_ORDER)  # TPM2B nonces size=0
    salt = (0).to_bytes(2, BYTE_ORDER)  # TPM2B size=0
    session_type = TPM_SE_HMAC.to_bytes(1, BYTE_ORDER)

    # symmetric = TPMT_SYM_DEF with algorithm = TPM_ALG_NULL
    symmetric = (
        TPM_ALG_NULL.to_bytes(2, BYTE_ORDER)  # algorithm
        + (0).to_bytes(2, BYTE_ORDER)  # keyBits (ignored for ALG_NULL)
        + (0).to_bytes(2, BYTE_ORDER)  # mode   (ignored for ALG_NULL)
    )

    auth_hash = TPM_ALG_SHA256.to_bytes(2, BYTE_ORDER)

    params = tpm_key + bind + nonce + salt + session_type + symmetric + auth_hash

    command_size = 2 + 4 + 4 + len(params)

    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
        + params
    )
    return cmd


def build_create_primary_with_session_cmd(fake_session_handle: int) -> bytes:
    """
    Build a TPM2_CreatePrimary command that *uses* a session handle.
    """
    tag = TPM_ST_SESSIONS
    cc = TPM_CC_CREATEPRIMARY
    primary_handle = TPM_RH_OWNER  # typical

    # Empty inSensitive
    in_sensitive = (0).to_bytes(2, BYTE_ORDER)  # size = 0

    # Minimal placeholder inPublic: just some bytes; likely invalid, but exercises parsing.
    in_public_payload = b"\x00\x01"
    in_public = len(in_public_payload).to_bytes(2, BYTE_ORDER) + in_public_payload

    # Empty outsideInfo
    outside_info = (0).to_bytes(2, BYTE_ORDER)  # size = 0

    # creationPCR: TPML_PCR_SELECTION with count = 0
    creation_pcr = (0).to_bytes(2, BYTE_ORDER)

    # Authorization area:
    # authAreaSize (4 bytes) followed by one TPMS_AUTH_COMMAND:
    #   sessionHandle (4)
    #   nonce.size (2) + nonce bytes
    #   sessionAttributes (1)
    #   hmac.size (2) + hmac bytes
    nonce = (0).to_bytes(2, BYTE_ORDER)
    session_attrs = b"\x00"
    hmac = (0).to_bytes(2, BYTE_ORDER)
    auth_cmd = (
        fake_session_handle.to_bytes(4, BYTE_ORDER) + nonce + session_attrs + hmac
    )
    auth_area_size = len(auth_cmd).to_bytes(4, BYTE_ORDER)

    body = (
        primary_handle.to_bytes(4, BYTE_ORDER)
        + in_sensitive
        + in_public
        + outside_info
        + creation_pcr
        + auth_area_size
        + auth_cmd
    )

    command_size = 2 + 4 + 4 + len(body)

    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
        + body
    )
    return cmd


def auth_area_pw():
    # authAreaSize + TPMS_AUTH_COMMAND
    auth_cmd = u32(TPM_RS_PW) + u16(0) + b"\x00" + u16(0)
    return u32(len(auth_cmd)) + auth_cmd


def build_in_public(
    hash_alg: int,
    key_bits: int,
    type_alg: int = TPM_ALG_RSA,
    scheme_alg: int = TPM_ALG_NULL,
) -> bytes:
    """
    Minimal but structured TPM2B_PUBLIC (RSA) – enough to be parsed.
    """
    # TPMT_PUBLIC
    name_alg = u16(hash_alg)
    object_attrs = u32(0x00060072)  # typical SRK-like attributes
    auth_policy = u16(0)

    rsa_params = (
        u16(type_alg)  # TPM_ALG_RSA
        + u16(scheme_alg)  # TPM_ALG_NULL (scheme)
        + u16(key_bits)  # keyBits
        + u32(0)  # exponent
    )

    unique = u16(0)  # empty unique field

    tpm_public = name_alg + object_attrs + auth_policy + rsa_params + unique
    return u16(len(tpm_public)) + tpm_public  # TPM2B_PUBLIC


def build_create_cmd(hash_alg: int, key_bits: int) -> bytes:
    handles = u32(PARENT_HANDLE)
    auth = auth_area_pw()

    in_sensitive = u16(0)
    in_public = build_in_public(hash_alg, key_bits)
    outside_info = u16(0)
    creation_pcr = u32(0)

    params = in_sensitive + in_public + outside_info + creation_pcr
    body = handles + auth + params

    size = 2 + 4 + 4 + len(body)
    return u16(TPM_ST_SESSIONS) + u32(size) + u32(TPM_CC_CREATE) + body


def tpm_create_primary_seeds() -> List[bytes]:
    """
    Multi-sequence seeds: StartAuthSession followed by CreatePrimary using
    a fake session handle. The fuzzer will execute both commands in one cycle.
    """
    seeds: List[bytes] = []

    # For fuzzing, just pick a fixed handle that looks like a session handle.
    fake_session_handle = 0x02000000

    start_sess_cmd = build_start_auth_session_cmd(fake_session_handle)
    create_prim_cmd = build_create_primary_with_session_cmd(fake_session_handle)

    # Multi-sequence seed = concatenation of both commands
    seeds.append(start_sess_cmd + create_prim_cmd)

    return seeds


def tpm_create_seeds():
    seeds = []
    hash_algs = [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384]
    key_bits = [1024, 2048]

    for h in hash_algs:
        for k in key_bits:
            seeds.append(build_create_cmd(h, k))

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
    for st in [TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS]:
        for bytes_requested in [16, 32, 64, 0, 48]:
            # NOTE: Command Size is Total number of input bytes including
            #       tag and command size.
            command_size = 2 + 4 + 4 + 2
            seed = (
                st.to_bytes(2, byteorder=BYTE_ORDER)
                + command_size.to_bytes(4, byteorder=BYTE_ORDER)
                + TPM_CC_GETRANDOM.to_bytes(4, byteorder=BYTE_ORDER)
                + bytes_requested.to_bytes(2, byteorder=BYTE_ORDER)
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

    for cmd, func in seeds.items():
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

        for i, seed in enumerate(seeds):
            filename = f"{cmd}-variant{i}-{current_timestamp}"
            filepath = os.path.join(directory, filename)
            with open(filepath, "wb") as f:
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
        ("sha1-owner", b"test hash data", TPM_ALG_SHA1, TPM_RH_OWNER),
        ("sha256-platform", b"another test", TPM_ALG_SHA256, TPM_RH_PLATFORM),
        ("sha384-null-random", b"random bytes", TPM_ALG_SHA384, TPM_RH_NULL),
    ]

    st = TPM_ST_NO_SESSIONS  # Same as standalone script

    for _name, data, alg, hier in cases:
        # TPM2B_MAX_BUFFER: UINT16 size + bytes
        params = (
            len(data).to_bytes(2, byteorder=BYTE_ORDER)
            + data
            + alg.to_bytes(2, byteorder=BYTE_ORDER)
            + hier.to_bytes(4, byteorder=BYTE_ORDER)
        )

        # Header: tag(2) + commandSize(4) + commandCode(4)
        command_size = 2 + 4 + 4 + len(params)
        cmd = (
            st.to_bytes(2, byteorder=BYTE_ORDER)
            + command_size.to_bytes(4, byteorder=BYTE_ORDER)
            + TPM_CC_HASH.to_bytes(4, byteorder=BYTE_ORDER)
            + params
        )

        seeds.append(cmd)

    return seeds


if __name__ == "__main__":
    # NOTE: Update this to include a seed function
    seeds = {
        "TPMGetRandom": tpm_get_rand_seeds,
        "TPMHash": tpm_hash_seeds,
        "TPMCreate": tpm_create_seeds,
        "TPMCreatePrimary": tpm_create_primary_seeds,
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

    generate_seeds(args.output_dir, args.recreate, seeds)

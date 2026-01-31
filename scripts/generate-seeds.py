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

from typing import List, Callable, Dict, Optional
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
TPM_CC_GETTESTRESULT = 0x0000017C

TPM_RH_NULL = 0x40000007
TPM_RH_OWNER = 0x40000001
TPM_RH_PLATFORM = 0x4000000C

TPM_ALG_RSA = 0x0001
TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_AES = 0x0006
TPM_ALG_CFB = 0x0043
TPM_ALG_NULL = 0x0010

TPM_SE_HMAC = 0x00
TPM_RS_PW = 0x40000009

TPMA_OBJECT_FIXEDTPM = 1 << 1
TPMA_OBJECT_FIXEDPARENT = 1 << 4
TPMA_OBJECT_SENSITIVEDATAORIGIN = 1 << 5
TPMA_OBJECT_USERWITHAUTH = 1 << 6
TPMA_OBJECT_NODA = 1 << 10
TPMA_OBJECT_DECRYPT = 1 << 17
TPMA_OBJECT_RESTRICTED = 1 << 16

# The First HMAC Session is typically this.
# Subsequent ones should be around the same HMAC Session
# Handle Range
TPM_FIRST_HMAC_SESSION_HANDLE = 0x02000000

RSA_STORAGE_OBJECT_ATTRS = (
    TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH
    | TPMA_OBJECT_NODA
    | TPMA_OBJECT_DECRYPT
    | TPMA_OBJECT_RESTRICTED
)


def build_in_public(alg: int, keybits: int) -> bytes:
    # -------------------------
    # inPublic: TPM2B_PUBLIC containing TPMT_PUBLIC
    # TPMT_PUBLIC = type | nameAlg | objectAttributes | authPolicy | parameters | unique
    # We'll build an RSA 2048 storage key template:
    # - type: RSA
    # - nameAlg: <alg>
    # - attrs: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|decrypt
    # - authPolicy: empty
    # - parameters: RSA detail (AES-128-CFB symmetric, scheme NULL, <keybits> bits, exponent 0)
    # - unique: empty (TPM generates)
    # -------------------------
    public_type = TPM_ALG_RSA.to_bytes(2, BYTE_ORDER)
    name_alg = alg.to_bytes(2, BYTE_ORDER)
    object_attrs = RSA_STORAGE_OBJECT_ATTRS.to_bytes(4, BYTE_ORDER)

    auth_policy = (0).to_bytes(2, BYTE_ORDER)  # TPM2B_DIGEST size = 0

    # TPMT_SYM_DEF_OBJECT for storage keys: algorithm AES, keyBits 128, mode CFB
    sym_alg = TPM_ALG_AES.to_bytes(2, BYTE_ORDER)
    sym_keybits = (128).to_bytes(2, BYTE_ORDER)
    sym_mode = TPM_ALG_CFB.to_bytes(2, BYTE_ORDER)
    symmetric_def_object = sym_alg + sym_keybits + sym_mode  # 6 bytes

    # TPMT_RSA_SCHEME: scheme = NULL (no extra details)
    rsa_scheme = TPM_ALG_NULL.to_bytes(2, BYTE_ORDER)
    rsa_keybits = (keybits).to_bytes(2, BYTE_ORDER)
    rsa_exponent = (0).to_bytes(4, BYTE_ORDER)
    rsa_parameters = symmetric_def_object + rsa_scheme + rsa_keybits + rsa_exponent

    # unique: TPM2B_PUBLIC_KEY_RSA = size(2) + bytes, empty requests TPM generate it
    unique_rsa = (0).to_bytes(2, BYTE_ORDER)

    public_area = (
        public_type
        + name_alg
        + object_attrs
        + auth_policy
        + rsa_parameters
        + unique_rsa
    )

    in_public = len(public_area).to_bytes(2, BYTE_ORDER) + public_area
    return in_public


def tpm_create_seeds(
    parent_handle: int, hash_alg: int, key_bits: int, session_handle: int = TPM_RS_PW
) -> bytes:
    tag = TPM_ST_SESSIONS
    cc = TPM_CC_CREATE
    # parent_handle = TPM_RH_OWNER

    # -------------------------
    # Authorization area
    # -------------------------
    # TPMS_AUTH_COMMAND:
    #   sessionHandle (4) = session_handle
    #   nonceTPM.size (2) = 0
    #   sessionAttributes (1) = 0
    #   hmac.size (2) = password length (0 for empty)
    auth_cmd = (
        session_handle.to_bytes(4, BYTE_ORDER)
        + (0).to_bytes(2, BYTE_ORDER)  # nonce size = 0
        + b"\x00"  # sessionAttributes
        + (0).to_bytes(2, BYTE_ORDER)  # password size = 0 (empty)
    )
    auth_area_size = len(auth_cmd).to_bytes(4, BYTE_ORDER)  # should be 9

    # -------------------------
    # inSensitive: TPM2B_SENSITIVE_CREATE
    # Empty payload is fine structurally.
    # -------------------------
    sensitive_payload = (0).to_bytes(2, BYTE_ORDER) + (0).to_bytes(2, BYTE_ORDER)
    in_sensitive = len(sensitive_payload).to_bytes(2, BYTE_ORDER) + sensitive_payload

    # -------------------------
    # inpublic: TPM2B_PUBLIC (RSA)
    # -------------------------
    in_public = build_in_public(hash_alg, key_bits)

    # -------------------------
    # outsideInfo: TPM2B_DATA (empty)
    # -------------------------
    outside_info = (0).to_bytes(2, BYTE_ORDER)

    # -------------------------
    # creationPCR: TPML_PCR_SELECTION with count = 0 (4 bytes)
    # -------------------------
    creation_pcr = (0).to_bytes(4, BYTE_ORDER)

    # -------------------------
    # Assemble command body
    # IMPORTANT: for TPM_ST_SESSIONS:
    #   handle(s) | authSize | authArea | parameters...
    # -------------------------
    body = (
        parent_handle.to_bytes(4, BYTE_ORDER)
        + auth_area_size
        + auth_cmd
        + in_sensitive
        + in_public
        + outside_info
        + creation_pcr
    )

    command_size = 2 + 4 + 4 + len(body)

    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
        + body
    )

    return [cmd]


def tpm_get_rand_seeds(specific_bytes: Optional[int] = None) -> List[bytes]:
    """
    Generates seeds for the TPM2_GetRandom Command. This
    function generates variants of the command based on
    collected interesting seeds from previous testing.

    Command Structure:
      [TPMI_ST_COMMAND_TAG(tag i.e TPM_ST_NO_SESSIONS)][UINT32(Command Size)]
      [TPM_CC(Command Code)][UINT16 (Bytes Requested Parameter)]
    """
    request_bytes = [specific_bytes] if specific_bytes else [16, 32, 64, 0, 48]
    seeds: List[bytes] = []
    for st in [TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS]:
        for bytes_requested in request_bytes:
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


def tpm_start_auth_session_seeds() -> bytes:
    """
    Build a TPM2_StartAuthSession command. The TPM will *return* a
    real session handle, but for fuzzing we only care about the command.
    This is a minimal, plausible HMAC session. The return session
    is in range 0x02xxxxxx; First one is 0x02000000
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
    nonce_bytes = os.urandom(16)
    nonce = len(nonce_bytes).to_bytes(2, BYTE_ORDER) + nonce_bytes  # TPM2B nonces
    salt = (0).to_bytes(2, BYTE_ORDER)  # TPM2B
    session_type = TPM_SE_HMAC.to_bytes(1, BYTE_ORDER)

    # symmetric = TPMT_SYM_DEF with algorithm = TPM_ALG_NULL
    symmetric = TPM_ALG_NULL.to_bytes(2, BYTE_ORDER)

    auth_hash = TPM_ALG_SHA256.to_bytes(2, BYTE_ORDER)

    params = tpm_key + bind + nonce + salt + session_type + symmetric + auth_hash

    command_size = 2 + 4 + 4 + len(params)

    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
        + params
    )
    return [cmd]


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


def tpm_create_primary_seeds(
    hash_alg: int, key_bits: int, session_handle: int = TPM_RS_PW
) -> List[bytes]:
    """
    Single seed that create a transient parent handle.
    """
    tag = TPM_ST_SESSIONS
    cc = TPM_CC_CREATEPRIMARY
    primary_handle = TPM_RH_OWNER

    # -------------------------
    # Authorization area
    # -------------------------
    # TPMS_AUTH_COMMAND:
    #   sessionHandle (4) = session_handle
    #   nonceTPM.size (2) = 0
    #   sessionAttributes (1) = 0
    #   hmac.size (2) = password length (0 for empty)
    auth_cmd = (
        session_handle.to_bytes(4, BYTE_ORDER)
        + (0).to_bytes(2, BYTE_ORDER)  # nonce size = 0
        + b"\x00"  # sessionAttributes
        + (0).to_bytes(2, BYTE_ORDER)  # password size = 0 (empty)
    )
    auth_area_size = len(auth_cmd).to_bytes(4, BYTE_ORDER)  # should be 9

    # -------------------------
    # inSensitive: TPM2B_SENSITIVE_CREATE
    # Empty payload is fine structurally.
    # -------------------------
    sensitive_payload = (0).to_bytes(2, BYTE_ORDER) + (0).to_bytes(2, BYTE_ORDER)
    in_sensitive = len(sensitive_payload).to_bytes(2, BYTE_ORDER) + sensitive_payload

    # -------------------------
    # inpublic: TPM2B_PUBLIC (RSA)
    # -------------------------
    in_public = build_in_public(hash_alg, key_bits)

    # -------------------------
    # outsideInfo: TPM2B_DATA (empty)
    # -------------------------
    outside_info = (0).to_bytes(2, BYTE_ORDER)

    # -------------------------
    # creationPCR: TPML_PCR_SELECTION with count = 0 (4 bytes)
    # -------------------------
    creation_pcr = (0).to_bytes(4, BYTE_ORDER)

    # -------------------------
    # Assemble command body
    # IMPORTANT: for TPM_ST_SESSIONS:
    #   handle(s) | authSize | authArea | parameters...
    # -------------------------
    body = (
        primary_handle.to_bytes(4, BYTE_ORDER)
        + auth_area_size
        + auth_cmd
        + in_sensitive
        + in_public
        + outside_info
        + creation_pcr
    )

    command_size = 2 + 4 + 4 + len(body)

    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
        + body
    )

    return [cmd]


def tpm_get_test_result_seeds():
    """
    Create seeds for the TPM2_GetTestResult command.
    """
    tag = TPM_ST_NO_SESSIONS
    cc = TPM_CC_GETTESTRESULT
    command_size = 2 + 4 + 4
    cmd = (
        tag.to_bytes(2, BYTE_ORDER)
        + command_size.to_bytes(4, BYTE_ORDER)
        + cc.to_bytes(4, BYTE_ORDER)
    )

    return [cmd]


def _run_commands(
    directory: str,
    cmd: str,
    command: SeedFunction | List[SeedFunction | bytes],
    timestamp: str,
):
    if callable(command):
        seeds: List[bytes] = []
        seeds = command()

        for i, seed in enumerate(seeds):
            filename = f"{cmd}-variant{i}-{timestamp}"
            filepath = os.path.join(directory, filename)
            with open(filepath, "wb") as f:
                f.write(seed)
            print(f"Generated seed file: {filename}")
    elif isinstance(command, list):
        for i, sequence in enumerate(command):
            seeds: List[bytes] = []

            for f in sequence:
                if callable(f):
                    seeds.extend(f())
                elif isinstance(f, bytes):
                    seeds.append(f)
                elif isinstance(f, list):
                    seeds.extend(f)

            filename = f"{cmd}-variant{i}-{timestamp}"
            filepath = os.path.join(directory, filename)
            with open(filepath, "wb") as f:
                for seed in seeds:
                    f.write(seed)
            print(f"Generated seed file: {filename}")


def _generate_seeds(
    directory: str,
    recreate: bool,
    seeds: Dict[str, SeedFunction | List[SeedFunction | bytes]],
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

        if seed_files:
            for seed_file in seed_files:
                if recreate:
                    print(f"Deleting seed file: {seed_file}")
                    os.remove(os.path.join(directory, seed_file))
                else:
                    print(f"Skipping existing seed file: {seed_file}")

            if not recreate:
                continue

        _run_commands(directory, cmd, _cmd, current_timestamp)


if __name__ == "__main__":
    # NOTE: Update this to include a seed function
    seeds = {
        "TPMGetRandom": tpm_get_rand_seeds,
        "TPMHash": tpm_hash_seeds,
        "TPMGetTestResult": tpm_get_test_result_seeds,
        "TPMCreatePrimary": [
            [tpm_create_primary_seeds(TPM_ALG_SHA256, 2048), tpm_get_rand_seeds(16)],
            [tpm_get_rand_seeds(32), tpm_create_primary_seeds(TPM_ALG_SHA256, 2048)],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
            ],
        ],
        "TPMCreate": [
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA256, 2048),
            ],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA256, 1024),
            ],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA1, 2048),
            ],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA1, 1024),
            ],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA384, 2048),
            ],
            [
                tpm_create_primary_seeds(TPM_ALG_SHA256, 2048),
                tpm_create_seeds(0x80000000, TPM_ALG_SHA384, 1024),
            ],
        ],
        "TPMStartAuthSessionHMAC": [
            [tpm_start_auth_session_seeds],
            [
                tpm_start_auth_session_seeds(),
                tpm_create_primary_seeds(
                    TPM_ALG_SHA256, 2048, TPM_FIRST_HMAC_SESSION_HANDLE
                ),
            ],
        ],
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

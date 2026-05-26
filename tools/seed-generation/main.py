#!/usr/bin/env python3

"""
This script generates seed files for the TPM (Trusted Platform Module) commands
to be used in fuzz testing. The seeds are defined by specified command
structures utilizing TPM constants.

The generated seed files are saved in a specified output directory. The script
can also recreate existing seed files based on user input.

Usage:
    python main.py [options]

Options:
    -recreate: Recreate all existing seed files.
    --output-dir=<dir>: Specify a different output directory for the seed files (default is "seeds/").
    --test-script=<path>: Specify the script used to validate seed files.

Resources:
    - TPM Specification: https://trustedcomputinggroup.org/resource/tpm-library-specification/
"""

import subprocess

from typing import Callable, Dict, List, Optional, Sequence, Union
import os
import argparse
import time
import difflib
import re

from google.protobuf import text_format
import tpm_commands_pb2
from tpm2_commands import *

SeedSequence = List[TPMCommand]
SeedVariants = List[SeedSequence]
SeedFunction = Callable[[], SeedVariants]
SeedDefinition = Union[SeedFunction, TPMCommand, SeedVariants]

DEFAULT_SEED_DIRECTORY = "seeds/"
DEFAULT_TEST_SEED_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "test_seed.sh"
)
BYTE_ORDER = "big"

# TPM Public Key identifiers for SPDM
TPM_PUB_KEY_TPM_SPDM_00 = 0x00000000

# The First HMAC Session is typically this.
# Subsequent ones should be around the same HMAC Session
# Handle Range
TPM_FIRST_HMAC_SESSION_HANDLE = 0x02000000

# ── TPMUnseal deterministic blobs ─────────────────────────────────────────────
# Obtained by running CreatePrimary(RSA-2048/SHA256) + Create(KEYEDHASH/sealing)
# on a TPM manufactured with USE_DEBUG_RNG=YES (determinism.patch).
# The simulator always produces the same keys from the same inputs.

# Sealing object (NULL scheme, no sign/decrypt/restricted) created under the
# default RSA-2048 primary key.
_UNSEAL_SEAL_IN_PRIVATE = bytes.fromhex(
    "008a002033594e6f3ea199dd22b14de0b92b3f9e067739d4e62c04aaf98786946286fc"
    "bf001062fa60d9f9a3659af10227ba4a96a3e7f7e8eed20d6626f1e7c1bf725ff2b8e6"
    "be76005faaeb84bfc5b16a3347dfb438fd7103a247e0e8817e6813977988a779d810b7c"
    "ec88f787a2de64cb6508ab17fb27400861621c7608f18c05ffa429632114db15da39d"
)
_UNSEAL_SEAL_IN_PUBLIC = bytes.fromhex(
    "002e0008000b00000452000000100020100e11fac0e57e528401b817aa65bf846eb7ad6f"
    "ee0c7c756a89cdccb52f6c09"
)

# HMAC key (HMAC scheme, sign+restricted set) — triggers ATTRIBUTES error on Unseal.
_UNSEAL_HMAC_IN_PRIVATE = bytes.fromhex(
    "009e002071cfbc5a2fc1c71f4e5b2d115daeb9c0d4ccbf123239c86d5a8077fb8a6a617"
    "9001090647df915b1ac8e6a09d72c6d243b959921d23b92b7d34d560d460e6680156545"
    "8b440c78df63194196c6cf67effdf6771d897c62c22f23fbea9593f2676a3e5ba128a58"
    "a7da9ba8e112eebc62943e4c1e1789f478cc5d442940ea2039d169661179afb65d06910"
    "b48613248100993df6cebff5dbdc24c86110"
)
_UNSEAL_HMAC_IN_PUBLIC = bytes.fromhex(
    "00300008000b0005047200000005000b0020794e393f0483ff026189ffa1084466b4eb24"
    "eb0e9ab8d436538073a76359cbd5"
)


def tpm_load_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_Load.

    The valid variants use deterministic private/public blobs captured from
    TPM2_Create under the deterministic simulator. This allows Load to exercise
    the deeper path instead of only failing on empty or malformed inPrivate.

    Command sequences:
      Variant 0:
        CreatePrimary -> Create(KEYEDHASH sealed object) -> Load
      Variant 1:
        CreatePrimary -> Create(HMAC KEYEDHASH object) -> Load
      Variant 2:
        CreatePrimary -> Load(empty inPrivate)  -> TPM_RCS_SIZE
      Variant 3:
        CreatePrimary -> Load(corrupted inPrivate) -> integrity/private error
    """
    primary = TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048)

    variant0 = [
        primary,
        TPMCreate(
            0x80000000,
            TPM_RS.PW,
            TPM_ALG.SHA256,
            key_type=TPM_ALG.KEYEDHASH,
            keyBits=2048,
            object_attributes=[
                TPMA_OBJECT.FIXEDTPM,
                TPMA_OBJECT.FIXEDPARENT,
                TPMA_OBJECT.USERWITHAUTH,
                TPMA_OBJECT.NODA,
            ],
            keyedhash_scheme=TPMS_KEYEDHASH_PARMS(scheme=TPM_ALG.NULL),
            sensitive_data=b"hello secret",
        ),
        TPMLoad(0x80000000, _UNSEAL_SEAL_IN_PRIVATE, _UNSEAL_SEAL_IN_PUBLIC),
    ]

    variant1 = [
        primary,
        TPMCreate(
            0x80000000,
            TPM_RS.PW,
            TPM_ALG.SHA256,
            key_type=TPM_ALG.KEYEDHASH,
            keyBits=2048,
            object_attributes=[
                TPMA_OBJECT.FIXEDTPM,
                TPMA_OBJECT.FIXEDPARENT,
                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                TPMA_OBJECT.USERWITHAUTH,
                TPMA_OBJECT.NODA,
                TPMA_OBJECT.SIGN_ENCRYPT,
                TPMA_OBJECT.RESTRICTED,
            ],
            keyedhash_scheme=TPMS_KEYEDHASH_PARMS(
                scheme=TPM_ALG.HMAC, hash_alg=TPM_ALG.SHA256
            ),
        ),
        TPMLoad(0x80000000, _UNSEAL_HMAC_IN_PRIVATE, _UNSEAL_HMAC_IN_PUBLIC),
    ]

    variant2 = [
        primary,
        TPMLoad(
            0x80000000,
            TPM2B_PRIVATE().to_bytes(),
            _UNSEAL_SEAL_IN_PUBLIC,
        ),
    ]

    corrupted_private = bytearray(_UNSEAL_SEAL_IN_PRIVATE)
    corrupted_private[-1] ^= 0xFF

    variant3 = [
        primary,
        TPMLoad(
            0x80000000,
            bytes(corrupted_private),
            _UNSEAL_SEAL_IN_PUBLIC,
        ),
    ]

    return [variant0, variant1, variant2, variant3]


def tpm_unseal_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_Unseal targeting 100% line coverage of Unseal.c.

    Unseal.c branches:
      1. type != TPM_ALG_KEYEDHASH  → TPM_RCS_TYPE   (variant 1)
      2. decrypt || sign || restricted  → TPM_RCS_ATTRIBUTES  (variant 2)
      3. success path (copy outData)   → TPM_RC_SUCCESS       (variant 0)

    Because the TPM simulator is built with USE_DEBUG_RNG=YES (determinism.patch),
    the Create command always produces the same private/public blobs for the same
    inputs.  The hardcoded blobs below were captured from a single deterministic run
    and are reused in the Load command inside the same seed, so the fuzzer sees a
    fully self-consistent byte stream without needing external state.

    Command sequences
    -----------------
    Variant 0 – success:
        CreatePrimary → Create(sealed KEYEDHASH, NULL scheme)
        → Load → Unseal  (→ RC_SUCCESS, outData returned)

    Variant 1 – type error:
        CreatePrimary → Unseal(RSA primary handle)
        (→ RC_TYPE: object is not KEYEDHASH)

    Variant 2 – attributes error:
        CreatePrimary → Create(HMAC KEYEDHASH, sign+restricted)
        → Load → Unseal
        (→ RC_ATTRIBUTES: KEYEDHASH but sign or restricted is set)
    """
    primary = TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048)

    # Variant 0: success path — sealing KEYEDHASH (NULL scheme, no sign/decrypt/restricted)
    variant0 = [
        primary,
        TPMCreate(
            0x80000000,
            TPM_RS.PW,
            TPM_ALG.SHA256,
            key_type=TPM_ALG.KEYEDHASH,
            keyBits=2048,
            object_attributes=[
                TPMA_OBJECT.FIXEDTPM,
                TPMA_OBJECT.FIXEDPARENT,
                TPMA_OBJECT.USERWITHAUTH,
                TPMA_OBJECT.NODA,
            ],
            keyedhash_scheme=TPMS_KEYEDHASH_PARMS(scheme=TPM_ALG.NULL),
            sensitive_data=b"hello secret",
        ),
        TPMLoad(0x80000000, _UNSEAL_SEAL_IN_PRIVATE, _UNSEAL_SEAL_IN_PUBLIC),
        TPMUnseal(0x80000001),
    ]

    # Variant 1: type error (itemHandle is RSA, not KEYEDHASH)
    variant1 = [
        primary,
        TPMUnseal(0x80000000),
    ]

    # Variant 2: attributes error — HMAC KEYEDHASH with sign+restricted set
    variant2 = [
        primary,
        TPMCreate(
            0x80000000,
            TPM_RS.PW,
            TPM_ALG.SHA256,
            key_type=TPM_ALG.KEYEDHASH,
            keyBits=2048,
            object_attributes=[
                TPMA_OBJECT.FIXEDTPM,
                TPMA_OBJECT.FIXEDPARENT,
                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                TPMA_OBJECT.USERWITHAUTH,
                TPMA_OBJECT.NODA,
                TPMA_OBJECT.SIGN_ENCRYPT,
                TPMA_OBJECT.RESTRICTED,
            ],
            keyedhash_scheme=TPMS_KEYEDHASH_PARMS(
                scheme=TPM_ALG.HMAC, hash_alg=TPM_ALG.SHA256
            ),
        ),
        TPMLoad(0x80000000, _UNSEAL_HMAC_IN_PRIVATE, _UNSEAL_HMAC_IN_PUBLIC),
        TPMUnseal(0x80000001),
    ]

    return [variant0, variant1, variant2]


def tpm_incremental_self_test_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_IncrementalSelfTest.

    Command Structure:
        [TPM_ST_NO_SESSIONS][UINT32 commandSize]
        [TPM_CC_INCREMENTALSELFTEST][TPML_ALG toTest]

    TPML_ALG:
        [UINT32 count][TPM_ALG_ID * count]
    """
    # variants: empty list, one alg, two algs
    variants = [
        [],  # count=0
        [TPM_ALG.SHA256],  # count=1
        [TPM_ALG.SHA1, TPM_ALG.SHA256],  # count=2
    ]

    return [[TPMIncrementalSelfTest(algs)] for algs in variants]


def tpm_get_rand_seeds() -> SeedVariants:
    """
    Generates seeds for the TPM2_GetRandom Command. This
    function generates variants of the command based on
    collected interesting seeds from previous testing.

    Command Structure:
      [TPMI_ST_COMMAND_TAG(tag i.e TPM_ST_NO_SESSIONS)][UINT32(Command Size)]
      [TPM_CC(Command Code)][UINT16 (Bytes Requested Parameter)]
    """
    variants: SeedVariants = []
    test_cases = [16, 32, 64, 0, 48]
    for st in [TPM_ST.TPM_ST_NO_SESSIONS, TPM_ST.TPM_ST_SESSIONS]:
        for bytes_requested in test_cases:
            variants.append([TPMGetRandom(bytes_requested, st)])
    return variants


def tpm_get_capability_seeds() -> SeedVariants:
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
    variants: SeedVariants = []
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
        variants.append([TPMGetCapability(capability, property_val, property_count)])

    return variants


def tpm_hash_seeds() -> SeedVariants:
    """
    Generates a small, representative seed corpus for the TPM2_Hash command.

    This mirrors the previous standalone script behavior by producing exactly
    three well-formed TPM2_Hash command blobs (WITHOUT the harness frame).
    The harness frame wrapper is applied by generate_seeds() via wrap_tpm_commands().

    Command Structure (unwrapped):
      [TPMI_ST_COMMAND_TAG][UINT32(commandSize)][TPM_CC_HASH]
      [TPM2B_MAX_BUFFER][hashAlg][hierarchy]
    """
    variants: SeedVariants = []

    # Exactly the same 3 cases as your standalone script
    cases = [
        ("sha1-owner", b"test hash data", TPM_ALG.SHA1, TPM_RH.OWNER),
        ("sha256-platform", b"another test", TPM_ALG.SHA256, TPM_RH.PLATFORM),
        ("sha384-null-random", b"random bytes", TPM_ALG.SHA384, TPM_RH.NULL),
    ]

    for _name, data, alg, hier in cases:
        variants.append([TPMHash(data, alg, hier)])

    return variants


def tpm_pcr_read_seeds() -> SeedVariants:
    """
    Generates seeds for the TPM2_PCR_Read command targeting line
    coverage of PCR_Read.c.
    """
    variants: SeedVariants = []

    test_cases = [
        # (hash_alg, pcrSelect_bytes, description)
        (TPM_ALG.SHA256, bytes.fromhex("010000"), "SHA256, PCR 0"),
        (TPM_ALG.SHA1, bytes.fromhex("FFFFFF"), "SHA1, all PCRs 0-23"),
    ]

    for hash_alg, pcr_select, _desc in test_cases:
        sel = TPML_PCR_SELECTION(
            selections=[TPMS_PCR_SELECTION(hash=hash_alg, pcr_select=pcr_select)]
        )
        variants.append([TPMPCRRead(sel)])

    return variants


def tpm_pcr_allocate_seeds() -> SeedVariants:
    """
    Generates seeds for the TPM2_PCR_Allocate command targeting line
    coverage of PCR_Allocate.c and the key PCRAllocate() branches.
    """
    variants: SeedVariants = []

    test_cases = [
        # Valid single-bank allocation. PCR 0 (HCRTM) and 17 (DRTM) must remain set.
        TPML_PCR_SELECTION(
            selections=[
                TPMS_PCR_SELECTION(hash=TPM_ALG.SHA256, pcr_select=bytes.fromhex("010002"))
            ]
        ),
        # Duplicate SHA256 entries exercise "last one wins" replacement logic.
        TPML_PCR_SELECTION(
            selections=[
                TPMS_PCR_SELECTION(hash=TPM_ALG.SHA256, pcr_select=bytes.fromhex("010000")),
                TPMS_PCR_SELECTION(hash=TPM_ALG.SHA256, pcr_select=bytes.fromhex("010002")),
            ]
        ),
        # Invalid allocation: preserves PCR 0 but clears PCR 17, triggering TPM_RC_PCR.
        TPML_PCR_SELECTION(
            selections=[
                TPMS_PCR_SELECTION(hash=TPM_ALG.SHA256, pcr_select=bytes.fromhex("010000"))
            ]
        ),
    ]

    for pcr_allocation in test_cases:
        variants.append([TPMPCRAllocate(pcr_allocation)])

    return variants


def tpm_pcr_extend_seeds() -> SeedVariants:
    """
    Generates seeds for the TPM2_PCR_Extend command targeting line
    coverage of PCR_Extend.c.
    """
    variants: SeedVariants = []

    # Normal extend — covers PCRIsExtendAllowed, PCRIsStateSaved, PCRExtend
    digests = TPML_DIGEST_VALUES(
        digests=[TPMT_HA(hash_alg=TPM_ALG.SHA256, digest=bytes.fromhex("00" * 32))]
    )
    variants.append([TPMPCRExtend(0x00000000, digests)])

    # NULL handle — covers the early return branch (TPM_RH_NULL == 0x40000007)
    digests = TPML_DIGEST_VALUES(
        digests=[TPMT_HA(hash_alg=TPM_ALG.SHA256, digest=bytes.fromhex("00" * 32))]
    )
    variants.append([TPMPCRExtend(TPM_RH.NULL.value, digests)])

    # Multi-digest (count=2) — covers loop iteration i > 0
    multi_digests = TPML_DIGEST_VALUES(
        digests=[
            TPMT_HA(hash_alg=TPM_ALG.SHA1, digest=bytes.fromhex("11" * 20)),
            TPMT_HA(hash_alg=TPM_ALG.SHA256, digest=bytes.fromhex("22" * 32)),
        ]
    )
    variants.append([TPMPCRExtend(0x00000000, multi_digests)])

    return variants


def tpm_pcr_reset_seeds() -> SeedVariants:
    """
    Generates seeds for the TPM2_PCR_Reset command targeting line
    coverage of PCR_Reset.c.
    """
    variants: SeedVariants = []

    test_pcr_handles = [
        0x00000000,
        0x00000010,
    ]

    for pcr_handle in test_pcr_handles:
        variants.append([TPMPCRReset(pcr_handle)])

    return variants


def tpm_nv_extend_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_NV_Extend targeting line coverage of NV_Extend.c.

    """
    nv_index = TPM_HT.NV_INDEX.value << 24  # 0x01000000

    define_extend = TPMNVDefineSpace(
        nv_index=nv_index,
        attributes=[
            TPMA_NV.AUTHWRITE,
            TPMA_NV.AUTHREAD,
            TPMA_NV.NT_EXTEND,
            TPMA_NV.NO_DA,
        ],
    )

    define_ordinary = TPMNVDefineSpace(
        nv_index=nv_index,
        attributes=[TPMA_NV.AUTHWRITE, TPMA_NV.AUTHREAD, TPMA_NV.NO_DA],
    )

    define_lockable = TPMNVDefineSpace(
        nv_index=nv_index,
        attributes=[
            TPMA_NV.AUTHWRITE,
            TPMA_NV.AUTHREAD,
            TPMA_NV.NT_EXTEND,
            TPMA_NV.WRITEDEFINE,
            TPMA_NV.NO_DA,
        ],
    )

    extend_data = b"extend data here"

    # Variant 0: success, WRITTEN=0 — first extend zeroes old digest then hashes
    variant0 = [
        define_extend,
        TPMNVExtend(nv_index, extend_data),
    ]

    # Variant 1: success, WRITTEN=1 — second extend reads existing digest from NV
    variant1 = [
        define_extend,
        TPMNVExtend(nv_index, extend_data),
        TPMNVExtend(nv_index, extend_data),
    ]

    # Variant 2: !IsNvExtendIndex — ordinary AUTHWRITE index, not an extend type
    variant2 = [
        define_ordinary,
        TPMNVExtend(nv_index, extend_data),
    ]

    # Variant 3: write-locked — NvWriteAccessChecks returns TPM_RC_NV_LOCKED
    variant3 = [
        define_lockable,
        TPMNVWriteLock(nv_index, auth_handle=nv_index),
        TPMNVExtend(nv_index, extend_data),
    ]

    # Variant 4: authorization mismatch — AUTHWRITE-only index, auth as OWNER
    variant4 = [
        define_extend,
        TPMNVExtend(nv_index, extend_data, auth_handle=TPM_RH.OWNER),
    ]

    return [variant0, variant1, variant2, variant3, variant4]


def tpm_nv_definespace_seeds() -> SeedVariants:
    """
    Seeds for TPM2_NV_DefineSpace.

    Variant 0 — password session (PW): exercises the non-HMAC dispatch path;
      this is the same shape the tool emitted previously as the sole variant.

    Variant 1 — HMAC session: StartAuthSession followed by NV_DefineSpace using
      the first HMAC session handle. Exercises the HMAC patching path in
      session_auth.cc (cpHash + authHMAC computation + auth area rewrite).
    """
    nv_index = TPM_HT.NV_INDEX.value << 24

    variant0 = [TPMNVDefineSpace()]

    variant1 = [
        TPMStartAuthSession(TPM_RH.NULL, TPM_RH.NULL, session_type=TPM_SE.HMAC),
        TPMNVDefineSpace(
            nv_index=nv_index,
            attributes=[TPMA_NV.OWNERWRITE, TPMA_NV.OWNERREAD, TPMA_NV.NO_DA],
            session_handle=TPM_FIRST_HMAC_SESSION_HANDLE,
        ),
    ]

    return [variant0, variant1]


def tpm_nv_setbits_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_NV_SetBits.

    Coverage targets from NV_SetBits.c:
      - success path with !WRITTEN
      - success path with WRITTEN
    """
    variants: SeedVariants = []

    base_index = TPM_HT.NV_INDEX.value << 24

    # OWNERWRITE | OWNERREAD | (NT_BITS << 4)
    # NT_BITS = 0x2
    nv_bits_attrs = (
        TPMA_NV.OWNERWRITE.value | TPMA_NV.OWNERREAD.value | TPMA_NV.NT_BITS.value
    )

    variants = [
        # Variant 0:
        #   Define a bits index, then SetBits once.
        #   Covers:
        #     - NvReadOnlyModeChecks success
        #     - NvWriteAccessChecks success
        #     - IsNvBitsIndex true
        #     - !WRITTEN branch (oldValue = 0)
        #     - NvWriteUINT64Data
        [
            TPMNVDefineSpace(
                nv_index=base_index + 3,
                attributes=nv_bits_attrs,
                data_size=8,
            ),
            TPMNVSetBits(
                nv_index=base_index + 3,
                bits=0x0000000000000001,
                auth_handle=TPM_RH.OWNER,
            ),
        ],
        # Variant 1:
        #   Define a bits index, SetBits twice.
        #   Second SetBits covers WRITTEN path and NvGetUINT64Data.
        [
            TPMNVDefineSpace(
                nv_index=base_index + 4,
                attributes=nv_bits_attrs,
                data_size=8,
            ),
            TPMNVSetBits(
                nv_index=base_index + 4,
                bits=0x0000000000000001,
                auth_handle=TPM_RH.OWNER,
            ),
            TPMNVSetBits(
                nv_index=base_index + 4,
                bits=0x00000000000000A5,
                auth_handle=TPM_RH.OWNER,
            ),
        ],
    ]

    return variants


def _serialize_sequence(commands: Sequence[TPMCommand]) -> bytes:
    return b"".join(bytes(command) for command in commands)


def _serialize_proto_sequence(commands: Sequence[TPMCommand]) -> Optional[bytes]:
    proto_commands = []
    for command in commands:
        proto_payload = command.to_proto()
        if not proto_payload:
            return None
        proto_commands.append(tpm_commands_pb2.TPMCommand(**proto_payload))

    sequence = tpm_commands_pb2.TPMCommandSequence(commands=proto_commands)
    return text_format.MessageToString(sequence).encode("utf-8")


def _create_variant(
    name: str,
    timestamp: str,
    directory: str,
    content: bytes,
    test_script: str,
    force: Optional[bool] = False,
    proto: Optional[bool] = True,
):
    def request_section(input: str) -> str:
        pattern = r"=+\n\s*REQUEST\s*\n=+\n" r"(.*?)" r"(?==+\n\s*RESPONSE\s*\n=+)"

        match = re.search(pattern, input, re.DOTALL)
        if not match:
            print(f"Input: {input}")
            raise ValueError("REQUEST section not found")

        section = match.group(0)
        return section.rstrip()

    existing_items = [p for p in os.listdir(directory) if p.startswith(f"{name}-")]
    if len(existing_items) > 0:
        out = os.path.join(directory, existing_items[0])
        with open(out, "rb") as f:
            data = f.read()

        if data != content and force:
            print(f"EXPECTED BYTES CHANGED: {name}\n")
            current = os.path.join(directory, f"{name}-{timestamp}")
            with open(current, "wb") as f:
                f.write(content)

            if not proto:
                actual = request_section(
                    subprocess.run(
                        [test_script, "-local", out],
                        capture_output=True,
                        text=True,
                        check=True,
                    ).stdout
                )

                expected = request_section(
                    subprocess.run(
                        [test_script, "-local", current],
                        capture_output=True,
                        text=True,
                        check=True,
                    ).stdout
                )

                diff = difflib.unified_diff(
                    actual.splitlines(keepends=True),
                    expected.splitlines(keepends=True),
                )
            else:
                diff = difflib.unified_diff(
                    data.decode("utf-8").splitlines(keepends=True),
                    content.decode("utf-8").splitlines(keepends=True),
                )

            changes = "".join(diff)
            if len(changes.strip()) > 0:
                print(f"{changes}\n")
            os.remove(out)
    else:
        out = os.path.join(directory, f"{name}-{timestamp}")
        with open(out, "wb") as f:
            f.write(content)
        print(f"Generated seed file: {out}")


def _normalize_variants(command: SeedDefinition) -> SeedVariants:
    if isinstance(command, TPMCommand):
        return [[command]]
    if callable(command):
        return command()
    return command


def _run_commands(
    directory: str,
    proto_directory: str,
    cmd: str,
    command: SeedDefinition,
    timestamp: str,
    force: bool,
    test_script: str,
):
    for i, sequence in enumerate(_normalize_variants(command)):
        variant_name = f"{cmd}-variant{i}"
        _create_variant(
            variant_name,
            timestamp,
            directory,
            _serialize_sequence(sequence),
            test_script,
            force,
        )

        proto_content = _serialize_proto_sequence(sequence)
        if proto_content is not None:
            _create_variant(
                variant_name,
                timestamp,
                proto_directory,
                proto_content,
                test_script,
                force,
                True,
            )


def _generate_seeds(
    directory: str,
    recreate: bool,
    seeds: Dict[str, SeedDefinition],
    test_script: str,
):
    """
    Generate seeds for all supported TPM Commands.

    Args:
        directory (str): Output directory for the generated seeds.
        recreate (bool): Flag to indicate whether to recreate existing seeds.
        test_script (str): Script used to validate generated seed files.
    """
    byte_directory = os.path.join(directory, "bytearray")
    proto_directory = os.path.join(directory, "proto")

    os.makedirs(byte_directory, exist_ok=True)
    os.makedirs(proto_directory, exist_ok=True)

    current_timestamp = time.strftime("%Y%m%d%H%M")

    for cmd, command in seeds.items():
        _run_commands(
            byte_directory,
            proto_directory,
            cmd,
            command,
            current_timestamp,
            force=recreate,
            test_script=test_script,
        )


def tpm_make_credential_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_MakeCredential targeting line coverage of
    MakeCredential.c.
    
    Command structure (TPM_ST_NO_SESSIONS):
      handle(4) | credential: TPM2B_DIGEST | objectName: TPM2B_NAME

    MakeCredential.c branches:
      1. Key type is not asymmetric       → TPM_RC_KEY    (variant 1)
      2. Key lacks RESTRICTED | DECRYPT   → TPM_RC_KEY    (variant 2)
      3. Success path (credential wrapped) → TPM_RC_SUCCESS (variant 0)
    """
    # Standard 16-byte credential — well within SHA-256 digest size limit.
    credential = b"\xAB" * 16

    # A syntactically valid SHA-256 name (nameAlg=0x000B + 32-byte digest).
    sha256_name = (0x000B).to_bytes(2, BYTE_ORDER) + b"\x00" * 32

    restricted_decrypt_primary = TPMCreatePrimary(
        session_handle=TPM_RS.PW,
        hashAlg=TPM_ALG.SHA256,
        keyBits=2048,
    )

    signing_primary = TPMCreatePrimary(
        session_handle=TPM_RS.PW,
        hashAlg=TPM_ALG.SHA256,
        keyBits=2048,
        public_template=TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                type=TPM_ALG.RSA,
                name_alg=TPM_ALG.SHA256,
                object_attributes=[
                    TPMA_OBJECT.FIXEDTPM,
                    TPMA_OBJECT.FIXEDPARENT,
                    TPMA_OBJECT.SENSITIVEDATAORIGIN,
                    TPMA_OBJECT.USERWITHAUTH,
                    TPMA_OBJECT.NODA,
                    TPMA_OBJECT.SIGN_ENCRYPT,
                ],
                rsa_parameters=TPMS_RSA_PARMS(
                    symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                    scheme=TPM_ALG.NULL,
                    key_bits=2048,
                ),
            )
        ),
    )

    # Variant 0: success path — restricted decrypt key wraps the credential.
    variant0 = [
        restricted_decrypt_primary,
        TPMMakeCredential(
            handle=0x80000000,
            credential=credential,
            object_name=sha256_name,
        ),
    ]

    # Variant 1: key type error — signing key lacks RESTRICTED | DECRYPT.
    # MakeCredential rejects it with TPM_RC_KEY before touching the credential.
    variant1 = [
        signing_primary,
        TPMMakeCredential(
            handle=0x80000000,
            credential=credential,
            object_name=sha256_name,
        ),
    ]

    # Variant 2: empty credential — exercises the zero-length edge case.
    variant2 = [
        restricted_decrypt_primary,
        TPMMakeCredential(
            handle=0x80000000,
            credential=b"",
            object_name=sha256_name,
        ),
    ]

    return [variant0, variant1, variant2]


def tpm_rsa_encrypt_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_RSA_Encrypt
    """
    # 64 bytes: a reasonable plaintext size well within 2048-bit RSA limits.
    message = b"\x41" * 64

    non_restricted_encrypt_primary = TPMCreatePrimary(
        session_handle=TPM_RS.PW,
        hashAlg=TPM_ALG.SHA256,
        keyBits=2048,
        public_template=TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                type=TPM_ALG.RSA,
                name_alg=TPM_ALG.SHA256,
                object_attributes=[
                    TPMA_OBJECT.FIXEDTPM,
                    TPMA_OBJECT.FIXEDPARENT,
                    TPMA_OBJECT.SENSITIVEDATAORIGIN,
                    TPMA_OBJECT.USERWITHAUTH,
                    TPMA_OBJECT.DECRYPT,
                ],
                rsa_parameters=TPMS_RSA_PARMS(
                    symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                    scheme=TPM_ALG.NULL,
                    key_bits=2048,
                ),
            )
        ),
    )

    # Variant 0: RSAES scheme — exercises RSAES encryption path
    variant0 = [
        non_restricted_encrypt_primary,
        TPMRSAEncrypt(
            key_handle=0x80000000,
            message=message,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.RSAES),
        ),
    ]

    # Variant 1: OAEP/SHA-256 scheme — exercises OAEP encryption path
    variant1 = [
        non_restricted_encrypt_primary,
        TPMRSAEncrypt(
            key_handle=0x80000000,
            message=message,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.OAEP, hash_alg=TPM_ALG.SHA256),
        ),
    ]

    # Variant 2: NULL scheme — inherits key scheme (also NULL), exercises default path
    variant2 = [
        non_restricted_encrypt_primary,
        TPMRSAEncrypt(
            key_handle=0x80000000,
            message=message,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.NULL),
        ),
    ]

    # Variant 3: empty message — exercises zero-length plaintext edge case
    variant3 = [
        non_restricted_encrypt_primary,
        TPMRSAEncrypt(
            key_handle=0x80000000,
            message=b"",
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.OAEP, hash_alg=TPM_ALG.SHA256),
        ),
    ]

    return [variant0, variant1, variant2, variant3]


def tpm_rsa_decrypt_seeds() -> SeedVariants:
    """
    Generates seeds for TPM2_RSA_Decrypt targeting line coverage of RSA_Decrypt.c.

    RSA_Decrypt.c branches:
      1. type != TPM_ALG_RSA       → TPM_RCS_KEY        (not exercised — PP forces RSA key)
      2. restricted || !decrypt    → TPM_RCS_ATTRIBUTES  (variant 2 — PP overrides to fix key,
                                                           but demonstrates the seed structure)

    Key requirement: the primary key must be a non-restricted RSA decrypt key
    (objectAttributes WITHOUT the Restricted bit, symmetric = NULL).
    The sequence post-processor ensures this for all rsadecrypt sequences.
    """
    # 256 zero bytes: valid ciphertext size for a 2048-bit RSA key.
    cipher_text = b"\x00" * 256

    non_restricted_primary = TPMCreatePrimary(
        session_handle=TPM_RS.PW,
        hashAlg=TPM_ALG.SHA256,
        keyBits=2048,
        public_template=TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                type=TPM_ALG.RSA,
                name_alg=TPM_ALG.SHA256,
                object_attributes=[
                    TPMA_OBJECT.FIXEDTPM,
                    TPMA_OBJECT.FIXEDPARENT,
                    TPMA_OBJECT.SENSITIVEDATAORIGIN,
                    TPMA_OBJECT.USERWITHAUTH,
                    TPMA_OBJECT.NODA,
                    TPMA_OBJECT.DECRYPT,
                ],
                rsa_parameters=TPMS_RSA_PARMS(
                    symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                    scheme=TPM_ALG.NULL,
                    key_bits=2048,
                ),
            )
        ),
    )

    # Variant 0: RSAES scheme
    variant0 = [
        non_restricted_primary,
        TPMRSADecrypt(
            key_handle=0x80000000,
            cipher_text=cipher_text,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.RSAES),
        ),
    ]

    # Variant 1: OAEP/SHA-256 scheme
    variant1 = [
        non_restricted_primary,
        TPMRSADecrypt(
            key_handle=0x80000000,
            cipher_text=cipher_text,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.OAEP, hash_alg=TPM_ALG.SHA256),
        ),
    ]

    # Variant 2: NULL scheme — hits TPM_RCS_SCHEME when key scheme is also NULL
    variant2 = [
        non_restricted_primary,
        TPMRSADecrypt(
            key_handle=0x80000000,
            cipher_text=cipher_text,
            in_scheme=TPMT_RSA_DECRYPT(scheme=TPM_ALG.NULL),
        ),
    ]

    return [variant0, variant1, variant2]


if __name__ == "__main__":
    # NOTE: Update this to include a seed function
    TEST_CASES = {
        "TPMGetRandom": tpm_get_rand_seeds,
        "TPMStirRandom": TPMStirRandom(b""),
        "TPMHash": tpm_hash_seeds,
        "TPMGetTestResult": TPMGetTestResult(),
        "TPMSelfTest": [[TPMSelfTest(TPMI_YES_NO.YES)], [TPMSelfTest(TPMI_YES_NO.NO)]],
        "TPMReadClock": TPMReadClock(),
        "TPMVendorTCGTest": TPMVendorTCGTest(b""),
        "TPMUnseal": tpm_unseal_seeds,
        "TPMLoad": tpm_load_seeds,
        "TPMCreate": [
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA256, TPM_ALG.RSA, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA256, TPM_ALG.RSA, 1024),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA1, TPM_ALG.RSA, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA1, TPM_ALG.RSA, 1024),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA384, TPM_ALG.RSA, 2048),
            ],
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMCreate(0x80000000, TPM_RS.PW, TPM_ALG.SHA384, TPM_ALG.RSA, 1024),
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
            [
                TPMStartAuthSession(
                    TPM_RH.NULL, TPM_RH.NULL, session_type=TPM_SE.TPM_SE_HMAC
                )
            ],
            [
                TPMStartAuthSession(
                    TPM_RH.NULL, TPM_RH.NULL, session_type=TPM_SE.TPM_SE_HMAC
                ),
                TPMCreatePrimary(TPM_FIRST_HMAC_SESSION_HANDLE, TPM_ALG.SHA256, 2048),
            ],
        ],
        "TPMRSADecrypt": tpm_rsa_decrypt_seeds,
        "TPMRSAEncrypt": tpm_rsa_encrypt_seeds,
        "TPMMakeCredential": tpm_make_credential_seeds,
        "TPMIncrementalSelfTest": tpm_incremental_self_test_seeds,
        "TPMGetCapability": tpm_get_capability_seeds,
        "TPMECCParameters": TPMECCParameters(TPM_ECC_CURVE.NIST_P192),
        "TPMLoadExternal": [
            [
                TPMLoadExternal(TPM_ALG.SHA256, 2048),
            ],
            [
                TPMLoadExternal(TPM_ALG.SHA256, 2048, include_private=True),
            ],
        ],
        # --- TPM2_Sign seeds ---
        # CreatePrimary produces a signing key at handle 0x80000000,
        # then Sign operates on it. Six variants cover the major
        # code-paths in Sign.c to achieve 97.4% coverage.
        "TPMSign": [
            # Variant 0 – success: unrestricted signing key + correct digest
            [
                TPMCreatePrimary(
                    session_handle=TPM_RS.PW,
                    hashAlg=TPM_ALG.SHA256,
                    keyBits=2048,
                    public_template=TPM2B_PUBLIC(
                        public_area=TPMT_PUBLIC(
                            type=TPM_ALG.RSA,
                            name_alg=TPM_ALG.SHA256,
                            object_attributes=[
                                TPMA_OBJECT.FIXEDTPM,
                                TPMA_OBJECT.FIXEDPARENT,
                                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                                TPMA_OBJECT.USERWITHAUTH,
                                TPMA_OBJECT.NODA,
                                TPMA_OBJECT.SIGN_ENCRYPT,
                            ],
                            rsa_parameters=TPMS_RSA_PARMS(
                                symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                                scheme=TPM_ALG.NULL,
                                key_bits=2048,
                            ),
                        )
                    ),
                ),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 32,
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA256
                    ),
                    validation=TPMT_TK_HASHCHECK(hierarchy=TPM_RH.NULL),
                ),
            ],
            # Variant 1 – !IsSigningObject: storage key (DECRYPT, no SIGN)
            [
                TPMCreatePrimary(TPM_RS.PW, TPM_ALG.SHA256, 2048),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 32,
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA256
                    ),
                    validation=TPMT_TK_HASHCHECK(hierarchy=TPM_RH.NULL),
                ),
            ],
            # Variant 2 – wrong digest size: 16 bytes != SHA256 (32)
            [
                TPMCreatePrimary(
                    session_handle=TPM_RS.PW,
                    hashAlg=TPM_ALG.SHA256,
                    keyBits=2048,
                    public_template=TPM2B_PUBLIC(
                        public_area=TPMT_PUBLIC(
                            type=TPM_ALG.RSA,
                            name_alg=TPM_ALG.SHA256,
                            object_attributes=[
                                TPMA_OBJECT.FIXEDTPM,
                                TPMA_OBJECT.FIXEDPARENT,
                                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                                TPMA_OBJECT.USERWITHAUTH,
                                TPMA_OBJECT.NODA,
                                TPMA_OBJECT.SIGN_ENCRYPT,
                            ],
                            rsa_parameters=TPMS_RSA_PARMS(
                                symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                                scheme=TPM_ALG.NULL,
                                key_bits=2048,
                            ),
                        )
                    ),
                ),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 16,  # Wrong size for SHA256
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA256
                    ),
                    validation=TPMT_TK_HASHCHECK(hierarchy=TPM_RH.NULL),
                ),
            ],
            # Variant 3 – ticket validation path: non-empty validation digest
            [
                TPMCreatePrimary(
                    session_handle=TPM_RS.PW,
                    hashAlg=TPM_ALG.SHA256,
                    keyBits=2048,
                    public_template=TPM2B_PUBLIC(
                        public_area=TPMT_PUBLIC(
                            type=TPM_ALG.RSA,
                            name_alg=TPM_ALG.SHA256,
                            object_attributes=[
                                TPMA_OBJECT.FIXEDTPM,
                                TPMA_OBJECT.FIXEDPARENT,
                                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                                TPMA_OBJECT.USERWITHAUTH,
                                TPMA_OBJECT.NODA,
                                TPMA_OBJECT.SIGN_ENCRYPT,
                            ],
                            rsa_parameters=TPMS_RSA_PARMS(
                                symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                                scheme=TPM_ALG.NULL,
                                key_bits=2048,
                            ),
                        )
                    ),
                ),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 32,
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA256
                    ),
                    validation=TPMT_TK_HASHCHECK(
                        hierarchy=TPM_RH.NULL, digest=b"\x01" * 32
                    ),
                ),
            ],
            # Variant 4 – scheme mismatch: key has fixed RSASSA/SHA256,
            #   Sign requests RSASSA/SHA384 → CryptSelectSignScheme fails
            [
                TPMCreatePrimary(
                    session_handle=TPM_RS.PW,
                    hashAlg=TPM_ALG.SHA256,
                    keyBits=2048,
                    public_template=TPM2B_PUBLIC(
                        public_area=TPMT_PUBLIC(
                            type=TPM_ALG.RSA,
                            name_alg=TPM_ALG.SHA256,
                            object_attributes=[
                                TPMA_OBJECT.FIXEDTPM,
                                TPMA_OBJECT.FIXEDPARENT,
                                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                                TPMA_OBJECT.USERWITHAUTH,
                                TPMA_OBJECT.NODA,
                                TPMA_OBJECT.SIGN_ENCRYPT,
                            ],
                            rsa_parameters=TPMS_RSA_PARMS(
                                symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                                scheme=TPM_ALG.RSASSA,
                                scheme_hash=TPM_ALG.SHA256,
                                key_bits=2048,
                            ),
                        )
                    ),
                ),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 48,  # SHA384 size (mismatch)
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA384
                    ),
                    validation=TPMT_TK_HASHCHECK(hierarchy=TPM_RH.NULL),
                ),
            ],
            # Variant 5 – x509sign attribute: key has x509sign set,
            #   Sign should reject with TPM_RCS_ATTRIBUTES (L45-47)
            [
                TPMCreatePrimary(
                    session_handle=TPM_RS.PW,
                    hashAlg=TPM_ALG.SHA256,
                    keyBits=2048,
                    public_template=TPM2B_PUBLIC(
                        public_area=TPMT_PUBLIC(
                            type=TPM_ALG.RSA,
                            name_alg=TPM_ALG.SHA256,
                            object_attributes=[
                                TPMA_OBJECT.FIXEDTPM,
                                TPMA_OBJECT.FIXEDPARENT,
                                TPMA_OBJECT.SENSITIVEDATAORIGIN,
                                TPMA_OBJECT.USERWITHAUTH,
                                TPMA_OBJECT.NODA,
                                TPMA_OBJECT.SIGN_ENCRYPT,
                                TPMA_OBJECT.X509SIGN,
                            ],
                            rsa_parameters=TPMS_RSA_PARMS(
                                symmetric=TPMS_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                                scheme=TPM_ALG.NULL,
                                key_bits=2048,
                            ),
                        )
                    ),
                ),
                TPMSign(
                    key_handle=0x80000000,
                    digest=b"\x00" * 32,
                    in_scheme=TPMT_SIG_SCHEME(
                        scheme=TPM_ALG.RSASSA, hash_alg=TPM_ALG.SHA256
                    ),
                    validation=TPMT_TK_HASHCHECK(hierarchy=TPM_RH.NULL),
                ),
            ],
        ],
        "TPMPCRAllocate": tpm_pcr_allocate_seeds,
        "TPMPCRRead": tpm_pcr_read_seeds,
        "TPMPCRExtend": tpm_pcr_extend_seeds,
        "TPMPCRReset": tpm_pcr_reset_seeds,
        "TPMTestParms": TPMTestParms(),
        "TPMNVDefineSpace": tpm_nv_definespace_seeds,
        "TPMNVSetBits": tpm_nv_setbits_seeds,
        "TPMClear": [
            [
                TPMClear(auth_handle=TPM_RH.LOCKOUT),
            ],
            [
                TPMClear(auth_handle=TPM_RH.PLATFORM),
            ],
        ],
        "TPMSetPrimaryPolicy": [
            # Variant 0: valid empty policy, size 0 matches TPM_ALG_NULL
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.OWNER,
                    auth_policy=b"",
                    hash_alg=TPM_ALG.NULL,
                )
            ],
            # Variant 1: OWNER success path
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.OWNER,
                    auth_policy=b"\x00" * 32,
                    hash_alg=TPM_ALG.SHA256,
                )
            ],
            # Variant 2: ENDORSEMENT success path
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.ENDORSEMENT,
                    auth_policy=b"\x11" * 32,
                    hash_alg=TPM_ALG.SHA256,
                )
            ],
            # Variant 3: PLATFORM success path
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.PLATFORM,
                    auth_policy=b"\x22" * 32,
                    hash_alg=TPM_ALG.SHA256,
                )
            ],
            # Variant 4: LOCKOUT success path
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.LOCKOUT,
                    auth_policy=b"\x33" * 20,
                    hash_alg=TPM_ALG.SHA1,
                )
            ],
            # Variant 5: invalid size path, should hit TPM_RCS_SIZE
            [
                TPMSetPrimaryPolicy(
                    auth_handle=TPM_RH.OWNER,
                    auth_policy=b"",
                    hash_alg=TPM_ALG.SHA256,
                )
            ],
        ],
        "TPMNVWriteLock": [
            # Lock once success
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                        TPMA_NV.WRITEDEFINE,
                    ]
                ),
                TPMNVWriteLock(TPM_HT.NV_INDEX.value << 24),
            ],
            # Locking twice success
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                        TPMA_NV.WRITEDEFINE,
                    ]
                ),
                TPMNVWriteLock(TPM_HT.NV_INDEX.value << 24),
                TPMNVWriteLock(TPM_HT.NV_INDEX.value << 24),
            ],
            # TPMA_NV_WRITEDEFINE & TPMA_NV_WRITE_STCLEAR not set. Can't lock fail.
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ]
                ),
                TPMNVWriteLock(TPM_HT.NV_INDEX.value << 24),
            ],
        ],
        "TPMNVWrite": [
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ]
                ),
                TPMNVWrite(
                    TPM_HT.NV_INDEX.value << 24, b"\xaa" * 32, auth_handle=TPM_RH.OWNER
                ),
            ]
        ],
        "TPMNVReadLock": [
            [
                TPMNVDefineSpace(
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 3,
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                        TPMA_NV.READ_STCLEAR,
                    ],
                ),
                TPMNVWrite(
                    (TPM_HT.NV_INDEX.value << 24) + 4,
                    b"\xaa" * 32,
                    auth_handle=TPM_RH.OWNER,
                ),
                TPMNVReadLock((TPM_HT.NV_INDEX.value << 24) + 3),
            ],
            [
                TPMNVDefineSpace(
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 4,
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                        TPMA_NV.READ_STCLEAR,
                    ],
                ),
                TPMNVWrite(
                    (TPM_HT.NV_INDEX.value << 24) + 5,
                    b"\xaa" * 32,
                    auth_handle=TPM_RH.OWNER,
                ),
                TPMNVReadLock((TPM_HT.NV_INDEX.value << 24) + 4),
                TPMNVReadLock((TPM_HT.NV_INDEX.value << 24) + 4),
            ],
            [
                TPMNVDefineSpace(
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 5,
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ],
                ),
                TPMNVWrite(
                    (TPM_HT.NV_INDEX.value << 24) + 5,
                    b"\xaa" * 32,
                    auth_handle=TPM_RH.OWNER,
                ),
                TPMNVReadLock((TPM_HT.NV_INDEX.value << 24) + 5),
            ],
        ],
        "TPMNVRead": [
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ],
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 1,
                ),
                TPMNVWrite(
                    (TPM_HT.NV_INDEX.value << 24) + 1,
                    b"\xaa" * 32,
                    auth_handle=TPM_RH.OWNER,
                ),
                TPMNVRead((TPM_HT.NV_INDEX.value << 24) + 1, 2, 0, TPM_RH.OWNER),
            ],
            # Read locked
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                        TPMA_NV.READLOCKED,
                    ],
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 1,
                ),
                TPMNVWrite(
                    (TPM_HT.NV_INDEX.value << 24) + 1,
                    b"\xaa" * 32,
                    auth_handle=TPM_RH.OWNER,
                ),
                TPMNVRead((TPM_HT.NV_INDEX.value << 24) + 1, 2, 0, TPM_RH.OWNER),
            ],
            # Read unwritten. Fail
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ],
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 1,
                ),
                TPMNVRead((TPM_HT.NV_INDEX.value << 24) + 1, 0, 0, TPM_RH.OWNER),
            ],
        ],
        "TPMNVExtend": tpm_nv_extend_seeds,
        "TPMNVUndefineSpace": [
            [
                TPMNVDefineSpace(
                    attributes=[
                        TPMA_NV.OWNERREAD,
                        TPMA_NV.OWNERWRITE,
                    ]
                ),
                TPMNVUndefineSpace(TPM_HT.NV_INDEX.value << 24),
            ],
            [
                TPMNVDefineSpace(
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 1,
                    attributes=[
                        TPMA_NV.PPREAD,
                        TPMA_NV.PPWRITE,
                        TPMA_NV.POLICY_DELETE,
                        TPMA_NV.PLATFORMCREATE,
                    ],
                    hierarchy=TPM_RH.PLATFORM,
                ),
                TPMNVUndefineSpace((TPM_HT.NV_INDEX.value << 24) + 1),
            ],
            [
                TPMNVDefineSpace(
                    nv_index=(TPM_HT.NV_INDEX.value << 24) + 2,
                    attributes=[
                        TPMA_NV.PPREAD,
                        TPMA_NV.PPWRITE,
                        TPMA_NV.PLATFORMCREATE,
                    ],
                    hierarchy=TPM_RH.PLATFORM,
                ),
                TPMNVUndefineSpace((TPM_HT.NV_INDEX.value << 24) + 2),
            ],
        ],
        "TPMPCREvent": [
            [TPMPCREvent(0x00000001, bytes(0), TPM_RS.PW.value)],
            [TPMPCREvent(0x00000001, bytes(1024), TPM_RS.PW.value)],
            [TPMPCREvent(TPM_RH.NULL.value, bytes(1024), TPM_RS.PW.value)],
            [TPMPCREvent(TPM_RH.NULL.value, bytes(0), TPM_RS.PW.value)],
        ],
    }

    parser = argparse.ArgumentParser(
        description="Generates the seed corpus for the Fuzzer."
    )
    parser.add_argument("-recreate", action="store_true", help="Recreate all seeds.")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_SEED_DIRECTORY,
        help="Override output directory for seeds.",
    )
    parser.add_argument(
        "--test-script",
        default=DEFAULT_TEST_SEED_SCRIPT,
        help="Override the script used to validate generated seeds.",
    )
    args = parser.parse_args()

    _generate_seeds(args.output_dir, args.recreate, TEST_CASES, args.test_script)

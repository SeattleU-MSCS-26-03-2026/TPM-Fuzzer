import struct
from pathlib import Path

# TPM constants
TPM_ST_NO_SESSIONS = 0x8001
TPM_CC_HASH = 0x0000017D

TPM_ALG_SHA1   = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C

TPM_RH_OWNER    = 0x40000001
TPM_RH_NULL     = 0x40000007
TPM_RH_PLATFORM = 0x4000000C

def tpm2_hash_cmd(data: bytes, hash_alg: int, hierarchy: int) -> bytes:
    # TPM2B_MAX_BUFFER: UINT16 size + bytes
    params = struct.pack(">H", len(data)) + data
    params += struct.pack(">H", hash_alg)
    params += struct.pack(">I", hierarchy)

    # Header: tag(2) + commandSize(4) + commandCode(4)
    command_size = 10 + len(params)
    header = struct.pack(">H", TPM_ST_NO_SESSIONS) + struct.pack(">I", command_size) + struct.pack(">I", TPM_CC_HASH)
    return header + params

def wrap_frame(cmd: bytes, locality: int = 0) -> bytes:
    # libFuzzer harness frame: locality(1) + len(4 be) + cmd bytes
    return struct.pack(">B", locality) + struct.pack(">I", len(cmd)) + cmd

out_dir = Path("corpus/TPM2_Hash")
out_dir.mkdir(parents=True, exist_ok=True)

seeds = [
    ("seed_sha1_owner_test_hash_data.bin", b"test hash data", TPM_ALG_SHA1,   TPM_RH_OWNER),
    ("seed_sha256_platform_another_test.bin", b"another test", TPM_ALG_SHA256, TPM_RH_PLATFORM),
    ("seed_sha384_null_random_bytes.bin", b"random bytes", TPM_ALG_SHA384, TPM_RH_NULL),
]

for name, data, alg, hier in seeds:
    cmd = tpm2_hash_cmd(data, alg, hier)
    blob = wrap_frame(cmd, locality=0)
    (out_dir / name).write_bytes(blob)

print(f"Wrote {len(seeds)} seeds to {out_dir}")

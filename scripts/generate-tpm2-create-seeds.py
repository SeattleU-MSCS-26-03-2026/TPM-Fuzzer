#!/usr/bin/env python3
"""
This script generates seed files for the TPM (Trusted Platform Module) TPM2_Create
command to be used in libFuzzer-based fuzz testing.

The seeds mirror the valid input combinations used in the previous Go fuzzer
implementation and encode:

    - Hash Algorithm (uint16, little-endian)
    - RSA Key Size in bits (uint16, little-endian)

Each seed file is 4 bytes:
    [0..1] = TPMIAlgHash (e.g., SHA1, SHA256, SHA384)
    [2..3] = RSA key size (1024, 2048)

The generated seed files are saved in the "seeds/" directory by default and are
used by the TPM2_Create fuzz target as its initial corpus.

Usage:
    python3 tools/generate_tpm2_create_seeds.py

Resources:
    - TPM Library Specification:
      https://trustedcomputinggroup.org/resource/tpm-library-specification/
"""

import os
import struct

OUT_DIR = "seeds"

TPM_ALGS = {
    "sha1":   0x0004,
    "sha256": 0x000B,
    "sha384": 0x000C,
}

RSA_KEY_SIZES = [1024, 2048]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    count = 0
    for alg_name, alg_id in TPM_ALGS.items():
        for bits in RSA_KEY_SIZES:
            fname = f"TPMCreate-{alg_name}-{bits}"
            path = os.path.join(OUT_DIR, fname)

            data = struct.pack("<HH", alg_id, bits)

            with open(path, "wb") as f:
                f.write(data)

            print(f"Generated {path}  (alg=0x{alg_id:04x}, bits={bits})")
            count += 1

    print(f"\nDone. Generated {count} seed files into '{OUT_DIR}/'.")

if __name__ == "__main__":
    main()

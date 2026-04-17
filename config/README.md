# TPM Determinism Patch

## How to Create the Patch

1. Clone the TPM repository locally:
```bash
git clone https://github.com/TrustedComputingGroup/TPM
cd TPM
```

2. Make your changes (edit any files you need to make deterministic):
```bash
vim TPMCmd/tpm/include/TpmBuildSwitches.h
vim TPMCmd/Platform/src/Entropy.c
# etc.
```

3. Generate the patch:
```bash
git diff > determinism.patch
```

4. Copy patch to this directory:
```bash
cp determinism.patch /path/to/fuzzer-project/patches/
```

5. Build with patch:
```bash
docker-compose build fuzzer
```

## Verifying Your Patch

After building, verify your changes were applied:
```bash
# Example: Check a specific file
docker compose run --rm fuzzer cat /tpm-src/path/to/your/file.h | grep YOUR_SETTING
```

## If Patch Fails to Apply

- TPM source code may have changed since you created the patch
- Regenerate the patch from a fresh clone
- Check that paths in your patch match the cloned repo structure

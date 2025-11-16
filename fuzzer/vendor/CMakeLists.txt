# Build only the TPM Libraries
set(Tpm_BuildOption_LibOnly TRUE)

# Provides:
# - TpmVendorCommands_Handlers
# - Tpm_CryptoLib_Math_Ossl
# - Tpm_CryptoLib_TpmBigNum
# - Tpm_CoreLib
add_subdirectory(TPM/TPMCmd)
# Provides:
# - TpmPlatformLib
add_subdirectory(TPM/TPMCmd/Platform)

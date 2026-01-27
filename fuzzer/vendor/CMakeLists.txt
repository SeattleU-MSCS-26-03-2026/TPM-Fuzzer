# Build only the TPM Libraries
set(Tpm_BuildOption_LibOnly TRUE)

# -----------------------------------------------------------
# Global Sanitizer & Coverage Flags
# -----------------------------------------------------------

add_compile_options(
    -g
    -fsanitize=fuzzer,address
    -fprofile-instr-generate
    -fcoverage-mapping
)

add_link_options(
    -fsanitize=fuzzer,address
    -fprofile-instr-generate
    -fcoverage-mapping
)

# Provides:
# - TpmVendorCommands_Handlers
# - Tpm_CryptoLib_Math_Ossl
# - Tpm_CryptoLib_TpmBigNum
# - Tpm_CoreLib
add_subdirectory(TPM/TPMCmd)
# Provides:
# - TpmPlatformLib
add_subdirectory(TPM/TPMCmd/Platform)

# Header-only interface for TPM headers. Link this
# library to have access to Simulator & TPM function
# definitions.
add_library(vendor INTERFACE)

target_link_libraries(vendor
  INTERFACE
    Tpm_Public_Headers::Tpm_Public_Headers
    Tpm_CoreLib::Tpm_CoreLib
    TpmConfiguration::TpmConfiguration
    Tpm_PlatformLib::Tpm_PlatformLib
    Tpm_Platform_Interface::Tpm_Platform_Interface
    Tpm_CryptoLib_TpmBigNum::Tpm_CryptoLib_TpmBigNum
    TpmVendorCommands_Handlers::TpmVendorCommands_Handlers
)

target_include_directories(vendor
  INTERFACE
    TPM/TPMCmd/Simulator/include
    TPM/TPMCmd/Simulator/include/prototypes
    TPM/TPMCmd/tpm/include
    TPM/TPMCmd/Simulator/src
)

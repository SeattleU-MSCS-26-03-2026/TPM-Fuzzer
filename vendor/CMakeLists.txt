# Build only the TPM Libraries
set(Tpm_BuildOption_LibOnly TRUE)

# -----------------------------------------------------------
# Global Sanitizer & Coverage Flags
# -----------------------------------------------------------

add_compile_options(
    -fsanitize=address,signed-integer-overflow,fuzzer-no-link
    -fprofile-instr-generate
    -fcoverage-mapping
)

add_link_options(
    -fsanitize=address,signed-integer-overflow,fuzzer-no-link
    -fprofile-instr-generate
    -fcoverage-mapping
)

set(LIB_PROTO_MUTATOR_TESTING OFF)
set(LIB_PROTO_MUTATOR_EXAMPLES OFF)
set(LIB_PROTO_MUTATOR_WITH_ASAN ON)
add_subdirectory(libprotobuf-mutator)

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
add_library(TPM INTERFACE)

target_link_libraries(TPM
  INTERFACE
    -Wl,--start-group
    Tpm_PlatformLib::Tpm_PlatformLib
    TpmVendorCommands_Handlers::TpmVendorCommands_Handlers
    Tpm_CoreLib::Tpm_CoreLib
    Tpm_CryptoLib_TpmBigNum::Tpm_CryptoLib_TpmBigNum
    Tpm_CryptoLib_Math_Ossl::Tpm_CryptoLib_Math_Ossl
    -Wl,--end-group
)

target_include_directories(TPM
  INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/TPM/TPMCmd/tpm/include
)

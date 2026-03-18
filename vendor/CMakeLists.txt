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
    ${CMAKE_CURRENT_LIST_DIR}/TPM/TPMCmd/tpm/include
    ${CMAKE_CURRENT_LIST_DIR}/libprotobuf-mutator
)

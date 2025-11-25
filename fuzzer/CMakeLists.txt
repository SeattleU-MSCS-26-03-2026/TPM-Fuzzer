cmake_minimum_required(VERSION 3.23)

# NOTE: This project requires the Clang compiler.
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_C_COMPILER "clang")

# Require C++ Standard 23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Export compile_commands.json for LSP.
# NOTE: Copy the configuration from build/compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(Fuzzer LANGUAGES CXX C)

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

#-----------------------------
# Vendor Libraries
#-----------------------------

# As of 11/15/2025 the TPM Reference code is only
# tested for OpenSSL version 1.1.x to 3.5.x
# NOTE: Build will fail if the version is not in that range
#       so we require it to be in the range.
find_package(OpenSSL 1.1...3.5.99 REQUIRED)
include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

add_subdirectory(vendor)

#-----------------------------
# Include project headers
#-----------------------------
add_subdirectory(include)

#-----------------------------
# Fuzzer Binary
#-----------------------------
add_executable(Fuzzer)

target_sources(Fuzzer
  PRIVATE
    src/fuzzer.cc
    src/harness/tpm_wrapper.c
    vendor/TPM/TPMCmd/Simulator/src/TPMCmdp.c
    vendor/TPM/TPMCmd/Simulator/src/TcpServer.c
)
target_link_libraries(Fuzzer
  PRIVATE
    include
    Tpm_PlatformLib::Tpm_PlatformLib
    Tpm_CoreLib::Tpm_CoreLib
)
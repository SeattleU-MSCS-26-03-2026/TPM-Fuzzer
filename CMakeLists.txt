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
# Set RUN_UNIT_TESTS Flag
# -----------------------------------------------------------

option(RUN_UNIT_TESTS "run unit tests" OFF)

if (ENABLE_TESTS)
  message(STATUS "Running unit tests ....")
endif()

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
    src/parser/byte_parser.cc
)
target_link_libraries(Fuzzer
  PRIVATE
    include
    Tpm_PlatformLib::Tpm_PlatformLib
    Tpm_CoreLib::Tpm_CoreLib
)

target_compile_options(Fuzzer
    PRIVATE
        -g
        -fsanitize=fuzzer,address
        -fprofile-instr-generate
        -fcoverage-mapping
)

target_link_options(Fuzzer
    PRIVATE
        -fsanitize=fuzzer,address
        -fprofile-instr-generate
        -fcoverage-mapping
)

#-----------------------------
# ProtoFuzzer Binary
#-----------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2 REQUIRED tss2-mu)
add_executable(proto-fuzzer)

target_sources(proto-fuzzer
  PRIVATE
    src/proto-fuzzer.cc
    src/harness/tpm_wrapper.c
    src/harness/proto_conversion.cc
    src/parser/byte_parser.cc
)

target_include_directories(proto-fuzzer
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${TSS2_INCLUDE_DIRS}
)
target_link_libraries(proto-fuzzer
  PRIVATE
    include
    Tpm_PlatformLib::Tpm_PlatformLib
    Tpm_CoreLib::Tpm_CoreLib
    protobuf-mutator-libfuzzer
    ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES}
    ${TSS2_LIBRARIES}
)
target_compile_options(proto-fuzzer
    PRIVATE
        -g
        -fsanitize=fuzzer,address,signed-integer-overflow
        -fprofile-instr-generate
        -fcoverage-mapping
        ${TSS2_CFLAGS_OTHERS}
)

find_package(absl CONFIG QUIET)
if(TARGET absl::log_internal_check_op)
  target_link_libraries(proto-fuzzer PRIVATE absl::log_internal_check_op)
endif()

target_link_options(proto-fuzzer
    PRIVATE
        -fsanitize=fuzzer,address,signed-integer-overflow
        -fprofile-instr-generate
        -fcoverage-mapping
)

#-----------------------------
# Tester Binary
#-----------------------------
add_executable(Tester)

target_sources(Tester
  PRIVATE
    src/tester.cc
    src/harness/tpm_wrapper.c
    src/parser/byte_parser.cc
)

target_link_libraries(Tester
  PRIVATE
    include
    Tpm_PlatformLib::Tpm_PlatformLib
    Tpm_CoreLib::Tpm_CoreLib
)

target_compile_options(Tester
    PRIVATE
        -g
        -fsanitize=address
        -fprofile-instr-generate
        -fcoverage-mapping
)

target_link_options(Tester
    PRIVATE
        -fsanitize=address
        -fprofile-instr-generate
        -fcoverage-mapping
)

# -----------------------------------------------------------
# Add Test Directory
# -----------------------------------------------------------

if (RUN_UNIT_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

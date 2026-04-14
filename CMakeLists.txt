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
# Project build options
# -----------------------------------------------------------
option(RUN_UNIT_TESTS "run unit tests" OFF)
option(LIB_ONLY "build only the reusable fuzzing framework" OFF)
option(BUILD_REFERENCE_WRAPPER "build the TCG TPM 2.0 Reference TPM Implementation wrapper" ON)
option(BUILD_LIBTPMS_WRAPPER "build the libtpms reference wrapper" OFF)

# -----------------------------
# Include TPM Harness libraries
# -----------------------------
add_subdirectory(include)

if (BUILD_LIBTPMS_WRAPPER)
    add_subdirectory(example)

    add_library(LibTPMSReference STATIC
        example/wrapper.cc
        src/harness/proto_conversion.cc
        src/parser/byte_parser.cc
    )

    target_link_libraries(LibTPMSReference
        PUBLIC
            libtpms
            TPMHarness
    )

    target_compile_options(LibTPMSReference
      PUBLIC
        -g
        -fsanitize=address,signed-integer-overflow,fuzzer-no-link
        -fprofile-instr-generate
        -fcoverage-mapping
    )

    target_link_options(LibTPMSReference
      PUBLIC
        -fsanitize=address,signed-integer-overflow,fuzzer-no-link
        -fprofile-instr-generate
        -fcoverage-mapping
    )
endif()

if (BUILD_REFERENCE_WRAPPER)
    # As of 11/15/2025 the TPM Reference code is only
    # tested for OpenSSL version 1.1.x to 3.5.x
    # NOTE: Build will fail if the version is not in that range
    #       so we require it to be in the range.
    find_package(OpenSSL 1.1...3.5.99 REQUIRED)
    include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

    add_subdirectory(vendor)

    add_library(TPMReference STATIC)

    target_sources(TPMReference
        PUBLIC
            src/harness/tpm_wrapper.c
            src/harness/proto_conversion.cc
            src/parser/byte_parser.cc
    )

    target_link_libraries(TPMReference
        PUBLIC
            vendor
            TPMHarness
    )
    target_compile_options(TPMReference
      PUBLIC
        -g
        -fsanitize=address,signed-integer-overflow,fuzzer-no-link
        -fprofile-instr-generate
        -fcoverage-mapping
    )

    target_link_options(TPMReference
      PUBLIC
        -fsanitize=address,signed-integer-overflow,fuzzer-no-link
        -fprofile-instr-generate
        -fcoverage-mapping
    )
endif()

if (NOT LIB_ONLY)
    # Unstructured Fuzzer Tester Binary
    add_executable(Tester)

    target_sources(Tester
        PRIVATE
            src/tester.cc
    )

    target_link_libraries(Tester
        PRIVATE
          TPMReference
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
    # Unstructured fuzzer
    add_executable(Fuzzer)

    target_sources(Fuzzer
      PRIVATE
        src/fuzzer.cc
    )
    target_link_libraries(Fuzzer
      PRIVATE
        TPMReference
        Tpm_PlatformLib::Tpm_PlatformLib
        Tpm_CoreLib::Tpm_CoreLib
    )

    target_compile_options(Fuzzer
      PRIVATE
        -g
        -fsanitize=fuzzer,address,signed-integer-overflow
        -fprofile-instr-generate
        -fcoverage-mapping
    )

    target_link_options(Fuzzer
      PRIVATE
        -fsanitize=fuzzer,address,signed-integer-overflow
        -fprofile-instr-generate
        -fcoverage-mapping
    )

    # Structured fuzzer
    add_executable(proto-fuzzer)

    target_sources(proto-fuzzer
        PRIVATE
            src/proto-fuzzer.cc
    )


    target_link_libraries(proto-fuzzer
        PRIVATE
            TPMReference
            Tpm_PlatformLib::Tpm_PlatformLib
            Tpm_CoreLib::Tpm_CoreLib
            protobuf-mutator-libfuzzer
            ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES}
    )

    find_package(absl CONFIG QUIET)
    if(TARGET absl::log_internal_check_op)
        target_link_libraries(Fuzzer PRIVATE absl::log_internal_check_op)
        target_link_libraries(proto-fuzzer PRIVATE absl::log_internal_check_op)
    endif()

    target_include_directories(proto-fuzzer
      PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libprotobuf-mutator
    )

    target_link_options(proto-fuzzer
        PRIVATE
            -fsanitize=fuzzer,address,signed-integer-overflow
            -fprofile-instr-generate
            -fcoverage-mapping
    )

    target_compile_options(proto-fuzzer
      PRIVATE
        -g
        -fsanitize=fuzzer,address,signed-integer-overflow
        -fprofile-instr-generate
        -fcoverage-mapping
    )
endif()

# -----------------------------------------------------------
# Add Test Directory
# -----------------------------------------------------------
if (RUN_UNIT_TESTS)
    message(STATUS "Running unit tests ....")
    enable_testing()
    add_subdirectory(tests)
endif()

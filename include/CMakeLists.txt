# NOTE: This CMake should be included after vendor
add_library(include INTERFACE)

target_link_libraries(include
  INTERFACE
    vendor
)

target_sources(include
  INTERFACE
  FILE_SET publicHeaders
  TYPE HEADERS
  FILES
    harness/common_headers.h
    harness/tpm_wrapper.h
    parser/byte_parser.h
)

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

set_target_properties(include PROPERTIES LINKER_LANGUAGE C)

# NOTE: This CMake should be included after vendor
find_package(Protobuf REQUIRED)
file(GLOB_RECURSE PROTO_FILES
  CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto
)

add_library(proto_generated STATIC)

protobuf_generate(
  TARGET proto_generated
  LANGUAGE cpp
  PROTOS ${PROTO_FILES}
  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/proto
  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto
)

target_include_directories(proto_generated
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/proto
)

target_link_libraries(proto_generated
  PUBLIC
    protobuf::libprotobuf
)

add_library(include INTERFACE)

target_link_libraries(include
  INTERFACE
    vendor
    proto_generated
)

target_sources(include
  INTERFACE
  FILE_SET publicHeaders
  TYPE HEADERS
  FILES
    harness/tpm_wrapper.h
    harness/proto_conversion.h
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

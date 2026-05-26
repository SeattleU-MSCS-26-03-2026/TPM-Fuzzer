find_package(Protobuf REQUIRED)
file(GLOB_RECURSE PROTO_FILES
  CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto
)

add_library(TPMFuzzerProtobufs STATIC)

protobuf_generate(
  TARGET TPMFuzzerProtobufs
  LANGUAGE cpp
  PROTOS ${PROTO_FILES}
  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/proto
  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto
)

protobuf_generate(
  TARGET TPMFuzzerProtobufs
  LANGUAGE python
  PROTOS ${PROTO_FILES}
  IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/proto
  PROTOC_OUT_DIR ${CMAKE_SOURCE_DIR}/tools/seed-generation
  GENERATE_EXTENSIONS .py _pb2.py
)

target_include_directories(TPMFuzzerProtobufs
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/proto
)

target_link_libraries(TPMFuzzerProtobufs
  PUBLIC
    protobuf::libprotobuf
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2 REQUIRED tss2-mu)

add_library(TPMHarness INTERFACE)

target_link_libraries(TPMHarness
  INTERFACE
    TPMFuzzerProtobufs
    ${TSS2_LIBRARIES}
)

target_sources(TPMHarness
  INTERFACE
  FILE_SET publicHeaders
  TYPE HEADERS
  FILES
    harness/proto_postprocessors.h
    harness/proto_normalization.h
    harness/proto_conversion.h
    harness/tpm_wrapper.h
    harness/session_auth.h
    harness/command_attributes.h
    parser/byte_parser.h
)

target_include_directories(TPMHarness
  INTERFACE
    ${TSS2_INCLUDE_DIRS}
)

target_compile_options(TPMHarness
  INTERFACE
    ${TSS2_CFLAGS_OTHERS}
)

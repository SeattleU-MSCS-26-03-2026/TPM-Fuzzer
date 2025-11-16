# NOTE: This CMake should be included after vendor
add_library(include INTERFACE)

target_link_libraries(include
  INTERFACE
    vendor
)

target_include_directories(include
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_sources(include
  INTERFACE
  FILE_SET publicHeaders
  TYPE HEADERS
  FILES
    harness/common_headers.h
    harness/tpm_wrapper.h
)

set_target_properties(include PROPERTIES LINKER_LANGUAGE C)

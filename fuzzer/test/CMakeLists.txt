find_package(Catch2 3 REQUIRED)

add_executable(FUZZER_TESTS
  parser/byte_parser_test.cc
  ${CMAKE_SOURCE_DIR}/src/parser/byte_parser.cc
)

target_link_libraries(FUZZER_TESTS
  PRIVATE
    Catch2::Catch2WithMain
)

target_include_directories(FUZZER_TESTS
  PRIVATE
    ${CMAKE_SOURCE_DIR}/include/parser
)

# Disable fuzz sanitizer for tests
target_compile_options(FUZZER_TESTS PRIVATE
  -fno-sanitize=fuzzer
)

target_link_options(FUZZER_TESTS PRIVATE
  -fno-sanitize=fuzzer
)

include(Catch)
catch_discover_tests(FUZZER_TESTS)
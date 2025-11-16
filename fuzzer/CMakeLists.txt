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

project(Fuzzer LANGUAGES CXX)

#-----------------------------
# Fuzzer Binary
#-----------------------------
add_executable(Fuzzer)
target_sources(Fuzzer
  PRIVATE
    src/fuzzer.cc
)

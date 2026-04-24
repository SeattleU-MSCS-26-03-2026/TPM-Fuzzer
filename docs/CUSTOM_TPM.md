# Custom TPM Implementation

The provided fuzz targets can be used to test your own custom TPM implementation. All you need to do is provide an implementation of the [wrapper functions](./include/harness/tpm_wrapper.h).

A minimal working example can be found in [./example](./example). Once the implementation has been configured and a library for it has been created, you can link any of the fuzz targets to your implementation to utilize them.

```cmake
add_executable(Fuzzer)

target_sources(Fuzzer
  PRIVATE
    src/fuzzer.cc
)
target_link_libraries(Fuzzer
  PRIVATE
    <Your Implementation>
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
```

## Add about determinism/ git patch + submodule
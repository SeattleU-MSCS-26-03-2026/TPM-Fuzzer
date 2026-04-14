set(LIBTPMS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libtpms)
set(LIBTPMS_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/libtpms-install)

include(ExternalProject)


set(SANITIZER_FLAGS "-fsanitize=address,signed-integer-overflow,fuzzer-no-link")
set(COVERAGE_FLAGS "-fcoverage-mapping -fprofile-instr-generate")
set(COMBINED_C_FLAGS "${SANITIZER_FLAGS} ${COVERAGE_FLAGS}")
set(COMBINED_LDFLAGS "${SANITIZER_FLAGS} ${COVERAGE_FLAGS}")

ExternalProject_Add(libtpms_ext
    SOURCE_DIR ${LIBTPMS_SOURCE_DIR}
    INSTALL_DIR ${LIBTPMS_INSTALL_DIR}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
        "CFLAGS=${COMBINED_C_FLAGS}"
        "LDFLAGS=${COMBINED_LDFLAGS}"
        ${LIBTPMS_SOURCE_DIR}/autogen.sh --with-openssl --with-tpm2 --prefix=<INSTALL_DIR> --disable-shared --enable-static
    BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 0
    BUILD_BYPRODUCTS ${LIBTPMS_INSTALL_DIR}/lib/libtpms.a ${LIBTPMS_INSTALL_DIR}/lib/libtpms.so
)

find_package(OpenSSL REQUIRED)

add_library(libtpms INTERFACE)
add_dependencies(libtpms libtpms_ext)

target_include_directories(libtpms INTERFACE ${LIBTPMS_INSTALL_DIR}/include)
target_link_directories(libtpms INTERFACE ${LIBTPMS_INSTALL_DIR}/lib)
target_link_libraries(libtpms INTERFACE tpms OpenSSL::SSL OpenSSL::Crypto)

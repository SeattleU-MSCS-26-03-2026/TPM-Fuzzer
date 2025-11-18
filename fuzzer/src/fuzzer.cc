/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code. Specifically
 * the `SendCommand` TPM API.
 */
// #include <harness/tpm_wrapper.h>

#include <arpa/inet.h>

#include <cstddef>
#include <cstring>

extern "C" {
#include <harness/tpm_wrapper.h>
}

#define MAX_BUFFER 1048576

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  size_t offset = 0;

  while (offset + 5 <= Size) {
    unsigned char locality = Data[offset];
    offset += 1;

    uint32_t length = 0;
    memcpy(&length, Data + offset, 4);
    length = ntohl(length);
    offset += 4;

    if (length > MAX_BUFFER || offset + length > Size) return 0;
    if (Size < 5 + length) return 0;

    char InputBuffer[MAX_BUFFER];

    memcpy(InputBuffer, Data + offset, length);
    offset += length;

    _IN_BUFFER request;
    request.Buffer = (uint8_t*)InputBuffer;
    request.BufferSize = length;

    _OUTPUT_BUFFER OutputBuffer;
    _OUT_BUFFER response;
    response.Buffer = OutputBuffer;
    response.BufferSize = MAX_BUFFER;

    TPMSendCommand(locality, request, &response);
  }

  return 0;
}

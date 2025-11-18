/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code. Specifically
 * the `SendCommand` TPM API.
 */
// #include <harness/tpm_wrapper.h>

#include <cstddef>

extern "C" {
#include <harness/tpm_wrapper.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  unsigned char locality = 0;

  _IN_BUFFER request;
  request.Buffer = (unsigned char*)Data;
  request.BufferSize = (unsigned int)Size;

  _OUTPUT_BUFFER responseBuf[4096];
  _OUT_BUFFER response;
  response.Buffer = *responseBuf;
  response.BufferSize = 4096;

  TPMSendCommand(locality, request, &response);

  return 0;
}

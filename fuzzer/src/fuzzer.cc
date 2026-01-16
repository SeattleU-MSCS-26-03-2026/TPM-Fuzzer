/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code. Specifically
 * the `SendCommand` TPM API.
 */

#include <parser/byte_parser.h>

#include <cstddef>
#include <vector>

extern "C" {
#include <harness/tpm_wrapper.h>
}

const size_t kMaxBuffers = 1048576;
const int kDefaultLocality = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  std::vector<std::vector<uint8_t>> commands;

  if (!parseCommands(Data, Size, commands)) {
    return 1;
  }

  // TPM start up sequence
  TPMSignalPowerOn(false);
  TPMSignalNvOn();

  for (auto& cmd : commands) {
    _IN_BUFFER request;
    request.Buffer = cmd.data();
    request.BufferSize = cmd.size();

    char OutputBuffer[kMaxBuffers];
    _OUT_BUFFER response;
    response.Buffer = (uint8_t*)OutputBuffer;
    response.BufferSize = kMaxBuffers;

    TPMSendCommand(kDefaultLocality, request, &response);
  }

  return 0;
}

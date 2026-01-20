/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code.
 */

#include <arpa/inet.h>
#include <parser/byte_parser.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include <harness/tpm_wrapper.h>
}

const size_t kMaxBuffers = 1048576;
const int kDefaultLocality = 0;

// Called for each fuzzing input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  std::vector<std::vector<uint8_t>> commands;
  if (!parseCommands(Data, Size, commands)) {
    return 1;
  }

  TPMManufactureIfNeeded();
  TPMStartup();

  for (auto& cmd : commands) {
    struct InBuffer request;
    request.buffer = cmd.data();
    request.buffer_size = cmd.size();

    char OutputBuffer[kMaxBuffers];
    struct OutBuffer response;
    response.buffer = (uint8_t*)OutputBuffer;
    response.buffer_size = kMaxBuffers;

    TPMSendCommand(kDefaultLocality, request, &response);
  }

  TPMShutdown();

  return 0;
}

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
const uint8_t kTPM2Startup[] = {
    // TPM2_ST_NO_SESSIONS header
    0x80, 0x01,              // tag: TPM_ST_NO_SESSIONS (0x8001)
    0x00, 0x00, 0x00, 0x0C,  // commandSize: 12 bytes (0x0000000C)
    0x00, 0x00, 0x01, 0x44,  // commandCode: TPM_CC_Startup (0x00000144)

    // Parameters
    0x00, 0x00  // startupType: TPM_SU_CLEAR (0x0000)
};

// Called for each fuzzing input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  std::vector<std::vector<uint8_t>> commands;
  if (!parseCommands(Data, Size, commands)) {
    return 1;
  }

  TPMManufactureIfNeeded();
  TPMStartup();

  // Send out TPM2_Startup
  {
    struct InBuffer startUpRequest;
    startUpRequest.buffer = kTPM2Startup;
    startUpRequest.buffer_size = sizeof(kTPM2Startup);

    char OutputBuffer[kMaxBuffers];
    struct OutBuffer response;
    response.buffer = (uint8_t*)OutputBuffer;
    response.buffer_size = kMaxBuffers;

    TPMSendCommand(kDefaultLocality, startUpRequest, &response);
  }

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

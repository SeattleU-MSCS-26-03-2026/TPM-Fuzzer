/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code.
 */

#include <parser/byte_parser.h>
#include <cstddef>
#include <vector>
#include <cstdio>

extern "C" {
#include <harness/tpm_wrapper.h>
}

const size_t kMaxBuffers = 1048576;
const int kDefaultLocality = 0;

// Called once when fuzzer starts
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  printf("=== TPM Fuzzer Initialization ===\n");
  
  // Step 1: Manufacture if needed (only runs if TPM not yet manufactured)
  TPMManufactureIfNeeded();
  
  // Step 2: Startup TPM for this fuzzing session
  TPMStartup();
  
  printf("=== TPM Ready for Fuzzing ===\n");
  return 0;
}

// Called for each fuzzing input
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
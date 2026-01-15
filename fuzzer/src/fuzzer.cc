/*
 * Fuzzer Binary
 *
 * This program is responsible for fuzzing the TPM Reference
 * https://github.com/TrustedComputingGroup/TPM source code. Specifically
 * the `SendCommand` TPM API.
 */

#include <arpa/inet.h>

#include <cstddef>
#include <cstring>
#include <vector>

extern "C" {
#include <harness/tpm_wrapper.h>
}

#define MAX_BUFFER 1048576
#define DEFAULT_LOCALITY 0
#define HEADER_TAG_LEN 2
#define HEADER_COMMAND_SIZE_LEN 4
#define HEADER_COMMAND_CODE_LEN 4

bool parseCommands(const uint8_t* Data, size_t Size,
                   std::vector<std::vector<uint8_t>>& commands) {
  size_t offset = 0;
  commands.clear();

  while (offset < Size) {
    if (offset + HEADER_TAG_LEN + HEADER_COMMAND_SIZE_LEN +
            HEADER_COMMAND_CODE_LEN >
        Size)
      return false;

    // TAG
    uint16_t tag;
    memcpy(&tag, Data + offset, HEADER_TAG_LEN);
    tag = ntohs(tag);

    if (tag != 0x8001 && tag != 0x8002) return false;

    // COMMAND LENGTH
    uint32_t length = 0;
    memcpy(&length, Data + offset + HEADER_TAG_LEN, HEADER_COMMAND_SIZE_LEN);
    length = ntohl(length);

    if (length <
        HEADER_TAG_LEN + HEADER_COMMAND_SIZE_LEN + HEADER_COMMAND_CODE_LEN)
      return false;
    if (offset + length > Size) return false;

    commands.emplace_back(Data + offset, Data + offset + length);

    offset += length;
  }

  return true;
}

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

    char OutputBuffer[MAX_BUFFER];
    _OUT_BUFFER response;
    response.Buffer = (uint8_t*)OutputBuffer;
    response.BufferSize = MAX_BUFFER;

    TPMSendCommand(DEFAULT_LOCALITY, request, &response);
  }

  return 0;
}

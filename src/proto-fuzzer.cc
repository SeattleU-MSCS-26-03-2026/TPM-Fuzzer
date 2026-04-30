#include <vector>

#include "harness/proto_postprocessors.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"

extern "C" {
#include <harness/tpm_wrapper.h>
}
#include "harness/proto_conversion.h"

namespace {
const bool kRegisteredPostProcessors = RegisterPostProcessors();

void ExecuteCommandBuffer(const std::vector<uint8_t>& command_buffer,
                          std::vector<uint8_t>* response_storage) {
  if (command_buffer.empty()) {
    return;
  }

  InBuffer request;
  request.buffer = command_buffer.data();
  request.buffer_size = command_buffer.size();

  OutBuffer response;
  response.buffer = response_storage->data();
  response.buffer_size = response_storage->size();

  TPMSendCommand(kDefaultLocality, request, &response);
}
}  // namespace

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) {
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();

  std::vector<uint8_t> command_buffer;
  std::vector<uint8_t> response_storage(kMaxBuffers);

  for (const auto& cmd : sequence.commands()) {
    if (!MarshalCommand(cmd, &command_buffer)) {
      continue;
    }
    ExecuteCommandBuffer(command_buffer, &response_storage);
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();
}

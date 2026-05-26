#include <vector>

#include "harness/proto_postprocessors.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"

extern "C" {
#include <harness/session_auth.h>
#include <harness/tpm_wrapper.h>
}
#include "harness/proto_conversion.h"

// Commands that have no active session or were not sent with a session
// tag (TPM_ST_SESSIONS) pass through the session auth functions unchanged.

namespace {
const bool kRegisteredPostProcessors = RegisterPostProcessors();

void ExecuteCommandBuffer(const uint8_t* buf, size_t size,
                          std::vector<uint8_t>* response_storage) {
  if (size == 0) return;

  InBuffer request;
  request.buffer = buf;
  request.buffer_size = size;

  OutBuffer response;
  response.buffer = response_storage->data();
  response.buffer_size = response_storage->size();

  TPMSendCommand(kDefaultLocality, request, &response);
  SessionAuthProcessResponse(response.buffer, response.buffer_size);
}
}  // namespace

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) {
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();
  SessionAuthReset();
  std::vector<uint8_t> command_buffer;
  std::vector<uint8_t> response_storage(kMaxBuffers);

  for (const auto& cmd : sequence.commands()) {
    if (!MarshalCommand(cmd, &command_buffer)) {
      continue;
    }
    size_t cmd_size = command_buffer.size();
    // Reserve extra space for the HMAC bytes added by SessionAuthPatchCommand.
    // Commands without a session are left untouched, so this resize is safe.
    if (command_buffer.size() < cmd_size + 64) {
      command_buffer.resize(cmd_size + 64);
    }
    cmd_size = SessionAuthPatchCommand(command_buffer.data(), cmd_size,
                                       command_buffer.size());
    ExecuteCommandBuffer(command_buffer.data(), cmd_size, &response_storage);
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();
}

#include <cstdint>
#include <vector>

#include "commands/tpm_getrandom.pb.h"
#include "constants/tpm_cc.pb.h"
#include "constants/tpm_st.pb.h"
#include "harness/proto_conversion.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"
#include "types/tpm_header.pb.h"

extern "C" {
#include <harness/tpm_wrapper.h>
}

namespace {

constexpr unsigned char kLocality = 0;
constexpr size_t kMaxResponseBuffer = 1024 * 1024;
constexpr uint32_t kMaxU16 = 0xFFFF;

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    commands::TPMGetRandom>
    reg = {[](commands::TPMGetRandom* msg, unsigned int /* seed */) {
      msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
      msg->mutable_header()->set_command_code(constants::TPM_CC_GET_RANDOM);
      msg->mutable_header()->set_command_size(12);

      if (msg->bytes_requested() == 0) msg->set_bytes_requested(1);
    }};

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

  TPMSendCommand(kLocality, request, &response);
}

}  // namespace

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) {
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();

  std::vector<uint8_t> command_buffer;
  std::vector<uint8_t> response_storage(kMaxResponseBuffer);

  for (const auto& cmd : sequence.commands()) {
    if (!MarshalCommand(cmd, &command_buffer)) {
      continue;
    }
    ExecuteCommandBuffer(command_buffer, &response_storage);
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();
}

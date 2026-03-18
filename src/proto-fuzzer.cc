#include <cstdint>
#include <cstdio>
#include <vector>

#include "constants/tpm_cc.pb.h"
#include "constants/tpm_st.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"
extern "C" {
#include <harness/tpm_wrapper.h>
}
namespace {

constexpr unsigned char kLocality = 0;
constexpr size_t kMaxResponseBuffer = 1024 * 1024;

// TPM wire-format constants for the first supported command.
constexpr uint16_t kTPM_ST_NO_SESSIONS =
    static_cast<uint16_t>(constants::TPM_ST_NO_SESSIONS);
constexpr uint32_t kTPM_CC_GET_RANDOM =
    static_cast<uint32_t>(constants::TPM_CC_GET_RANDOM);

void AppendU16BE(std::vector<uint8_t>& buf, uint16_t value) {
  buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

void AppendU32BE(std::vector<uint8_t>& buf, uint32_t value) {
  buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

void ExecuteCommandBuffer(const std::vector<uint8_t>& command_buffer) {
  if (command_buffer.empty()) return;

  InBuffer request;
  request.buffer = command_buffer.data();
  request.buffer_size = command_buffer.size();

  std::vector<uint8_t> response_storage(kMaxResponseBuffer);
  OutBuffer response;
  response.buffer = response_storage.data();
  response.buffer_size = response_storage.size();

  TPMSendCommand(kLocality, request, &response);
}

std::vector<uint8_t> SerializeGetRandom(const commands::TPMGetRandom& msg) {
  std::vector<uint8_t> buffer;

  // TPM2_GetRandom parameter is UINT16 bytesRequested.
  const uint16_t bytes_requested =
      static_cast<uint16_t>(msg.bytes_requested() & 0xFFFF);

  // Header is 10 bytes:
  //   tag (2) + commandSize (4) + commandCode (4)
  // GetRandom parameters are 2 bytes.
  const uint32_t command_size = 12;

  AppendU16BE(buffer, kTPM_ST_NO_SESSIONS);
  AppendU32BE(buffer, command_size);
  AppendU32BE(buffer, kTPM_CC_GET_RANDOM);
  AppendU16BE(buffer, bytes_requested);

  return buffer;
}

std::vector<uint8_t> SerializeCommand(const tpm::TPMCommand& command) {
  switch (command.command_case()) {
    case tpm::TPMCommand::kGetrandom: {
      const auto& msg = command.getrandom();

      return SerializeGetRandom(msg);
    }

    case tpm::TPMCommand::kCreate:
      // TODO.
      return {};

    case tpm::TPMCommand::kCreateprimary:
      // TODO.
      return {};

    case tpm::TPMCommand::COMMAND_NOT_SET:
    default:
      return {};
  }
}

}  // namespace

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) {
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();

  for (const auto& cmd : sequence.commands()) {
    const auto buffer = SerializeCommand(cmd);
    ExecuteCommandBuffer(buffer);
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();
}

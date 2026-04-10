#include "commands/tpm_getrandom.pb.h"
#include "tpm_commands.pb.h"
#include "tss2_common.h"
#include "tss2_mu.h"

static bool MUCommandFailed(TSS2_RC rc) { return rc != TSS2_RC_SUCCESS; }

/// Marshals the TPM Command Header (Service Tag, Command Size & Command Code)
/// into a byte array.
static bool MarshalCommandHeader(const types::TPMHeader& header,
                                 std::vector<uint8_t>* buf, size_t& offset) {
  size_t start = offset;
  if (MUCommandFailed(Tss2_MU_UINT16_Marshal(static_cast<UINT16>(header.tag()),
                                             buf->data(), buf->size(),
                                             &offset))) {
    return false;
  }

  if (MUCommandFailed(Tss2_MU_UINT32_Marshal(header.command_size(), buf->data(),
                                             buf->size(), &offset))) {
    return false;
  }

  if (MUCommandFailed(Tss2_MU_UINT32_Marshal(header.command_code(), buf->data(),
                                             buf->size(), &offset))) {
    return false;
  }

  // TPM Command Header is always 10 bytes
  return (offset - start) == 10;
}

/// Marshals a TPM Command into a byte array that can be understood by a TPM 2.0
/// compliant implementation.
bool MarshalCommand(const tpm::TPMCommand& command, std::vector<uint8_t>* out);

bool MarshalCommandField(const google::protobuf::Message& parent,
                         const google::protobuf::FieldDescriptor& field,
                         const google::protobuf::Reflection& reflection,
                         std::vector<uint8_t>* buf, size_t& offset);

bool MarshalTPMCommand(const google::protobuf::Message& cmd,
                       std::vector<uint8_t>* buf, size_t& offset);

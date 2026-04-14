#include "commands/tpm_createprimary.pb.h"
#include "commands/tpm_getrandom.pb.h"
#include "commands/tpm_startauthsession.pb.h"
#include "tpm_commands.pb.h"
#include "tss2_common.h"
#include "tss2_mu.h"
#include "types/tpm2b_data.pb.h"
#include "types/tpm2b_public.pb.h"
#include "types/tpm2b_sensitive_create.pb.h"
#include "types/tpm_session.pb.h"
#include "types/tpml_pcr_selection.pb.h"
#include "types/tpmt_sym_def.pb.h"

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

/// Patches the commandSize field (bytes [2-5]) with the actual buffer size.
static void PatchCommandSize(std::vector<uint8_t>* buf, size_t total_size) {
  size_t tmp = 2;  // commandSize starts at byte offset 2
  Tss2_MU_UINT32_Marshal(static_cast<UINT32>(total_size), buf->data(),
                         buf->size(), &tmp);
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

// Generic field dispatcher — handles repeated, message, enum, uint32, bytes.
bool MarshalCommandField(const google::protobuf::Message& parent,
                         const google::protobuf::FieldDescriptor& field,
                         const google::protobuf::Reflection& reflection,
                         std::vector<uint8_t>* buf, size_t& offset);

// Dispatches a protobuf message to the correct type-specific marshaler.
bool MarshalMessageField(const google::protobuf::Message& child,
                         std::vector<uint8_t>* buf, size_t& offset);

// Handles repeated fields (e.g. TPMSession authorization area).
bool MarshalRepeatedField(const google::protobuf::Message& parent,
                          const google::protobuf::FieldDescriptor& field,
                          const google::protobuf::Reflection& reflection,
                          std::vector<uint8_t>* buf, size_t& offset);

// Type-specific marshalers.
bool MarshalTPM2BData(const types::TPM2BData& data, std::vector<uint8_t>* buf,
                      size_t& offset);

bool MarshalTPMTSymDef(const types::TPMTSymDef& sym, std::vector<uint8_t>* buf,
                       size_t& offset);

bool MarshalTPMSession(const types::TPMSession& session,
                       std::vector<uint8_t>* buf, size_t& offset);

bool MarshalTPM2BSensitiveCreate(const types::TPM2BSensitiveCreate& sens,
                                 std::vector<uint8_t>* buf, size_t& offset);

bool MarshalTPM2BPublic(const types::TPM2BPublic& pub,
                        std::vector<uint8_t>* buf, size_t& offset);

bool MarshalTPMLPCRSelection(const types::TPMLPCRSelection& pcr,
                             std::vector<uint8_t>* buf, size_t& offset);

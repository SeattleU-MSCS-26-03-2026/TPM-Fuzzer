#include "harness/proto_conversion.h"

#include <limits>

#include "tss2_common.h"

constexpr size_t kMaxBuffer = 1024 * 1024;

bool MarshalCommand(const tpm::TPMCommand& command, std::vector<uint8_t>* out) {
  out->clear();
  out->resize(kMaxBuffer);
  size_t offset = 0;

  const auto* descriptor = command.GetDescriptor();
  const auto* reflection = command.GetReflection();
  const auto* oneof = descriptor->FindOneofByName("command");
  if (!oneof) return false;

  const auto* selected = reflection->GetOneofFieldDescriptor(command, oneof);
  if (!selected) return false;

  const auto& msg = reflection->GetMessage(command, selected);

  if (!MarshalTPMCommand(msg, out, offset)) return false;

  out->resize(offset);
  return true;
}

bool MarshalTPMCommand(const google::protobuf::Message& cmd,
                       std::vector<uint8_t>* buf, size_t& offset) {
  const auto* descriptor = cmd.GetDescriptor();
  const auto* reflection = cmd.GetReflection();

  if (!descriptor || !reflection) return false;

  for (int i = 0; i < descriptor->field_count(); i++) {
    const google::protobuf::FieldDescriptor* field = descriptor->field(i);
    if (!field) return false;

    if (!MarshalCommandField(cmd, *field, *reflection, buf, offset)) {
      return false;
    }
  }
  return true;
}

bool MarshalCommandField(const google::protobuf::Message& parent,
                         const google::protobuf::FieldDescriptor& field,
                         const google::protobuf::Reflection& reflection,
                         std::vector<uint8_t>* buf, size_t& offset) {
  switch (field.cpp_type()) {
    case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE: {
      const auto& child = reflection.GetMessage(parent, &field);
      const auto* childDescriptor = child.GetDescriptor();

      if (!childDescriptor) return false;

      std::string name = std::string(childDescriptor->full_name());
      // Handle any message types in a TPM Command per the proto i.e TPMHeader
      if (name == "types.TPMHeader") {
        const auto* header = dynamic_cast<const types::TPMHeader*>(&child);
        if (!header) return false;

        return MarshalCommandHeader(*header, buf, offset);
      }

      // Unknown type; Early fail
      return false;
    }
    case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
      // SPECIAL: Bytes Requested in the Proto is a UINT32 but in spec is a
      // UINT16
      const int32_t value = reflection.GetUInt32(parent, &field);
      if (field.name() == "bytes_requested") {
        if (value > std::numeric_limits<UINT16>::max()) {
          return false;
        }

        return !MUCommandFailed(Tss2_MU_UINT16_Marshal(
            static_cast<UINT16>(value), buf->data(), buf->size(), &offset));
      }

      return !MUCommandFailed(Tss2_MU_UINT32_Marshal(
          static_cast<UINT32>(value), buf->data(), buf->size(), &offset));
    }

    default:
      return false;
  }
}

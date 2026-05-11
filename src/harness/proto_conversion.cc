#include "harness/proto_conversion.h"

#include <cstring>
#include <limits>
#include <string>

#include "tss2_common.h"

constexpr size_t kMaxBuffer = 1024 * 1024;

template <typename Tpm2b>
static void FillTpm2b(const std::string& src, Tpm2b* dst) {
  const size_t copy_len = std::min(src.size(), sizeof(dst->buffer));
  dst->size = static_cast<uint16_t>(copy_len);
  if (copy_len > 0) {
    std::memcpy(dst->buffer, src.data(), copy_len);
  }
}

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

  PatchCommandSize(out, offset);
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
  // Handle repeated fields (e.g. sessions authorization area).
  if (field.is_repeated()) {
    return MarshalRepeatedField(parent, field, reflection, buf, offset);
  }

  switch (field.cpp_type()) {
    case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE: {
      const auto& child = reflection.GetMessage(parent, &field);
      return MarshalMessageField(child, buf, offset);
    }

    case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
      const size_t value =
          static_cast<size_t>(reflection.GetEnumValue(parent, &field));
      const std::string& enum_type =
          field.enum_type() ? std::string(field.enum_type()->full_name()) : "";

      // TPMSE is a single byte on the wire.
      if (enum_type == "constants.TPMSE") {
        if (offset >= buf->size()) return false;
        (*buf)[offset++] = static_cast<uint8_t>(value);
        return true;
      }

      // TPMALG values are UINT16 on the wire.
      if (enum_type == "constants.TPMALG") {
        return !MUCommandFailed(Tss2_MU_UINT16_Marshal(
            static_cast<UINT16>(value), buf->data(), buf->size(), &offset));
      }

      // Everything else (TPMRH, TPMCC, TPMST, etc.) is UINT32.
      return !MUCommandFailed(Tss2_MU_UINT32_Marshal(
          static_cast<UINT32>(value), buf->data(), buf->size(), &offset));
    }

    case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
      // SPECIAL: Bytes Requested in the Proto is a UINT32 but in spec is a
      // UINT16
      const uint32_t value = reflection.GetUInt32(parent, &field);
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

    case google::protobuf::FieldDescriptor::CPPTYPE_STRING: {
      // Raw bytes fields — write directly into the buffer.
      const std::string data = reflection.GetString(parent, &field);
      if (data.empty()) return true;
      if (offset + data.size() > buf->size()) return false;
      memcpy(buf->data() + offset, data.data(), data.size());
      offset += data.size();
      return true;
    }

    default:
      return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MarshalMessageField — dispatches on the protobuf message type name.
// ─────────────────────────────────────────────────────────────────────────────
bool MarshalMessageField(const google::protobuf::Message& child,
                         std::vector<uint8_t>* buf, size_t& offset) {
  const auto* desc = child.GetDescriptor();
  if (!desc) return false;

  const std::string name = std::string(desc->full_name());

  if (name == "tpm_types.TPMHeader") {
    const auto* header = dynamic_cast<const tpm_types::TPMHeader*>(&child);
    if (!header) return false;
    return MarshalCommandHeader(*header, buf, offset);
  }

  if (name == "tpm_types.TPM2BData") {
    const auto* data = dynamic_cast<const tpm_types::TPM2BData*>(&child);
    if (!data) return false;
    return MarshalTPM2BData(*data, buf, offset);
  }

  if (name == "tpm_types.TPMTSymDef") {
    const auto* sym = dynamic_cast<const tpm_types::TPMTSymDef*>(&child);
    if (!sym) return false;
    return MarshalTPMTSymDef(*sym, buf, offset);
  }

  if (name == "tpm_types.TPM2BSensitiveCreate") {
    const auto* sens =
        dynamic_cast<const tpm_types::TPM2BSensitiveCreate*>(&child);
    if (!sens) return false;
    return MarshalTPM2BSensitiveCreate(*sens, buf, offset);
  }

  if (name == "tpm_types.TPM2BPublic") {
    const auto* pub = dynamic_cast<const tpm_types::TPM2BPublic*>(&child);
    if (!pub) return false;
    return MarshalTPM2BPublic(*pub, buf, offset);
  }

  if (name == "tpm_types.TPMLPCRSelection") {
    const auto* pcr = dynamic_cast<const tpm_types::TPMLPCRSelection*>(&child);
    if (!pcr) return false;
    return MarshalTPMLPCRSelection(*pcr, buf, offset);
  }

  if (name == "tpm_types.TPM2BPublicKeyRSA") {
    const auto* rsa = dynamic_cast<const tpm_types::TPM2BPublicKeyRSA*>(&child);
    if (!rsa) return false;
    return MarshalTPM2BPublicKeyRSA(*rsa, buf, offset);
  }

  if (name == "tpm_types.TPMTRSADecrypt") {
    const auto* scheme = dynamic_cast<const tpm_types::TPMTRSADecrypt*>(&child);
    if (!scheme) return false;
    return MarshalTPMTRSADecrypt(*scheme, buf, offset);
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MarshalRepeatedField — handles repeated message fields.
// For TPMSession, writes an authorizationSize prefix, then each session.
// ─────────────────────────────────────────────────────────────────────────────
bool MarshalRepeatedField(const google::protobuf::Message& parent,
                          const google::protobuf::FieldDescriptor& field,
                          const google::protobuf::Reflection& reflection,
                          std::vector<uint8_t>* buf, size_t& offset) {
  const int count = reflection.FieldSize(parent, &field);

  if (field.cpp_type() != google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
    return false;

  // Check if this is a TPMSession repeated field.
  const std::string& msg_type = std::string(field.message_type()->full_name());
  if (msg_type != "tpm_types.TPMSession") return false;

  // Write authorizationSize placeholder.
  const size_t auth_size_pos = offset;
  if (MUCommandFailed(
          Tss2_MU_UINT32_Marshal(0, buf->data(), buf->size(), &offset)))
    return false;

  const size_t auth_area_start = offset;

  for (int i = 0; i < count; ++i) {
    const auto& session_msg = reflection.GetRepeatedMessage(parent, &field, i);
    const auto* session =
        dynamic_cast<const tpm_types::TPMSession*>(&session_msg);
    if (!session) return false;
    if (!MarshalTPMSession(*session, buf, offset)) return false;
  }

  // Patch authorizationSize.
  const uint32_t auth_area_size =
      static_cast<uint32_t>(offset - auth_area_start);
  size_t tmp = auth_size_pos;
  if (MUCommandFailed(Tss2_MU_UINT32_Marshal(auth_area_size, buf->data(),
                                             buf->size(), &tmp)))
    return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Type-specific marshalers
// ─────────────────────────────────────────────────────────────────────────────

bool MarshalTPM2BData(const tpm_types::TPM2BData& data,
                      std::vector<uint8_t>* buf, size_t& offset) {
  TPM2B_DATA tpm_data = {};
  FillTpm2b(data.buffer(), &tpm_data);

  return !MUCommandFailed(
      Tss2_MU_TPM2B_DATA_Marshal(&tpm_data, buf->data(), buf->size(), &offset));
}

bool MarshalTPMTSymDef(const tpm_types::TPMTSymDef& sym,
                       std::vector<uint8_t>* buf, size_t& offset) {
  TPMT_SYM_DEF symmetric = {};
  // Only AES and NULL are valid TPMI_ALG_SYM selectors in our enum.
  TPMI_ALG_SYM alg = static_cast<TPMI_ALG_SYM>(sym.algorithm());
  if (alg != TPM2_ALG_AES && alg != TPM2_ALG_NULL) alg = TPM2_ALG_NULL;
  symmetric.algorithm = alg;

  if (symmetric.algorithm != TPM2_ALG_NULL) {
    symmetric.keyBits.aes = static_cast<TPM2_KEY_BITS>(sym.key_bits());
    symmetric.mode.aes = static_cast<TPMI_ALG_SYM_MODE>(sym.mode());
  }

  return !MUCommandFailed(Tss2_MU_TPMT_SYM_DEF_Marshal(&symmetric, buf->data(),
                                                       buf->size(), &offset));
}

bool MarshalTPMSession(const tpm_types::TPMSession& session,
                       std::vector<uint8_t>* buf, size_t& offset) {
  // sessionHandle
  if (MUCommandFailed(Tss2_MU_UINT32_Marshal(
          session.session_handle(), buf->data(), buf->size(), &offset)))
    return false;

  // nonce: TPM2B = size(2) + bytes
  {
    const std::string& nonce_data = session.nonce();
    uint16_t nonce_size = static_cast<uint16_t>(nonce_data.size());
    if (MUCommandFailed(Tss2_MU_UINT16_Marshal(nonce_size, buf->data(),
                                               buf->size(), &offset)))
      return false;
    if (nonce_size > 0) {
      if (offset + nonce_size > buf->size()) return false;
      memcpy(buf->data() + offset, nonce_data.data(), nonce_size);
      offset += nonce_size;
    }
  }

  // sessionAttributes: 1 byte
  if (offset >= buf->size()) return false;
  (*buf)[offset++] = static_cast<uint8_t>(session.session_attributes());

  // hmac: TPM2B = size(2) + bytes
  {
    const std::string& hmac_data = session.hmac();
    uint16_t hmac_size = static_cast<uint16_t>(hmac_data.size());
    if (MUCommandFailed(Tss2_MU_UINT16_Marshal(hmac_size, buf->data(),
                                               buf->size(), &offset)))
      return false;
    if (hmac_size > 0) {
      if (offset + hmac_size > buf->size()) return false;
      memcpy(buf->data() + offset, hmac_data.data(), hmac_size);
      offset += hmac_size;
    }
  }

  return true;
}

bool MarshalTPM2BSensitiveCreate(
    const tpm_types::TPM2BSensitiveCreate& sens_proto,
    std::vector<uint8_t>* buf, size_t& offset) {
  TPM2B_SENSITIVE_CREATE in_sensitive = {};

  if (sens_proto.has_sensitive()) {
    const auto& s = sens_proto.sensitive();

    if (s.has_user_auth()) {
      FillTpm2b(s.user_auth().buffer(), &in_sensitive.sensitive.userAuth);
    }

    if (s.has_data()) {
      FillTpm2b(s.data().buffer(), &in_sensitive.sensitive.data);
    }
  }

  return !MUCommandFailed(Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal(
      &in_sensitive, buf->data(), buf->size(), &offset));
}

bool MarshalTPM2BPublic(const tpm_types::TPM2BPublic& pub_proto,
                        std::vector<uint8_t>* buf, size_t& offset) {
  TPM2B_PUBLIC in_public = {};
  // Default to NULL so TPMU_PUBLIC_PARMS/TPMU_PUBLIC_ID marshaling skips
  // the union when no parameters variant is set. 0x0 is not a valid selector.
  in_public.publicArea.type = TPM2_ALG_NULL;

  if (pub_proto.has_public_area()) {
    const auto& pa = pub_proto.public_area();

    // type is derived from the parameters oneof below — don't use pa.type()
    // (TPM_ALG_UNSPECIFIED (0x0), is not a valid selector)
    in_public.publicArea.nameAlg = static_cast<TPMI_ALG_HASH>(pa.name_alg());
    in_public.publicArea.objectAttributes =
        static_cast<TPMA_OBJECT>(pa.object_attributes());

    if (pa.has_auth_policy()) {
      FillTpm2b(pa.auth_policy().buffer(), &in_public.publicArea.authPolicy);
    }

    if (pa.has_parameters()) {
      const auto& parms = pa.parameters();

      if (parms.has_rsa()) {
        in_public.publicArea.type = TPM2_ALG_RSA;
        const auto& rsa = parms.rsa();
        // Only AES and NULL are valid TPMI_ALG_SYM_OBJECT selectors in our
        // enum.
        TPMI_ALG_SYM_OBJECT sym_alg =
            static_cast<TPMI_ALG_SYM_OBJECT>(rsa.symmetric());
        if (sym_alg != TPM2_ALG_AES && sym_alg != TPM2_ALG_NULL)
          sym_alg = TPM2_ALG_NULL;
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = sym_alg;

        if (sym_alg != TPM2_ALG_NULL) {
          in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes =
              static_cast<TPM2_KEY_BITS>(rsa.symmetric_key_bits());
          in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes =
              TPM2_ALG_CFB;
        }

        TPMI_ALG_ASYM_SCHEME scheme_alg =
            static_cast<TPMI_ALG_ASYM_SCHEME>(rsa.scheme());
        if (scheme_alg != TPM2_ALG_RSASSA && scheme_alg != TPM2_ALG_NULL)
          scheme_alg = TPM2_ALG_NULL;
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = scheme_alg;
        in_public.publicArea.parameters.rsaDetail.keyBits =
            static_cast<TPM2_KEY_BITS>(rsa.key_bits());
        in_public.publicArea.parameters.rsaDetail.exponent = rsa.exponent();
      } else if (parms.has_keyedhash()) {
        in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
        const auto& kh = parms.keyedhash();
        // Only HMAC, XOR, and NULL are valid TPMU_SCHEME_KEYEDHASH selectors.
        TPMI_ALG_KEYEDHASH_SCHEME kh_scheme =
            static_cast<TPMI_ALG_KEYEDHASH_SCHEME>(kh.scheme());
        if (kh_scheme != TPM2_ALG_HMAC && kh_scheme != TPM2_ALG_XOR &&
            kh_scheme != TPM2_ALG_NULL)
          kh_scheme = TPM2_ALG_NULL;
        in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
            kh_scheme;
      } else {
        in_public.publicArea.type = TPM2_ALG_NULL;
      }
    } else {
      in_public.publicArea.type = TPM2_ALG_NULL;
    }

    if (pa.has_unique()) {
      const auto& uid = pa.unique();
      if (in_public.publicArea.type == TPM2_ALG_RSA && uid.has_rsa()) {
        FillTpm2b(uid.rsa(), &in_public.publicArea.unique.rsa);
      } else if (in_public.publicArea.type == TPM2_ALG_KEYEDHASH &&
                 uid.has_keyedhash()) {
        FillTpm2b(uid.keyedhash().buffer(),
                  &in_public.publicArea.unique.keyedHash);
      }
    }
  }

  return !MUCommandFailed(Tss2_MU_TPM2B_PUBLIC_Marshal(&in_public, buf->data(),
                                                       buf->size(), &offset));
}

bool MarshalTPMLPCRSelection(const tpm_types::TPMLPCRSelection& pcr_proto,
                             std::vector<uint8_t>* buf, size_t& offset) {
  TPML_PCR_SELECTION creation_pcr = {};

  int sel_count = pcr_proto.pcr_selections_size();
  if (sel_count > TPM2_NUM_PCR_BANKS) sel_count = TPM2_NUM_PCR_BANKS;
  creation_pcr.count = static_cast<UINT32>(sel_count);

  for (int i = 0; i < sel_count; ++i) {
    const auto& sel = pcr_proto.pcr_selections(i);
    creation_pcr.pcrSelections[i].hash = static_cast<TPMI_ALG_HASH>(sel.hash());
    size_t sizeof_select = sel.sizeof_select();
    if (sizeof_select > sizeof(creation_pcr.pcrSelections[i].pcrSelect)) {
      sizeof_select = sizeof(creation_pcr.pcrSelections[i].pcrSelect);
    }
    creation_pcr.pcrSelections[i].sizeofSelect =
        static_cast<uint8_t>(sizeof_select);
    const std::string& pcr_data = sel.pcr_select();
    size_t copy_len = pcr_data.size();
    if (copy_len > sizeof_select) copy_len = sizeof_select;
    memcpy(creation_pcr.pcrSelections[i].pcrSelect, pcr_data.data(), copy_len);
  }

  return !MUCommandFailed(Tss2_MU_TPML_PCR_SELECTION_Marshal(
      &creation_pcr, buf->data(), buf->size(), &offset));
}

bool MarshalTPM2BPublicKeyRSA(const tpm_types::TPM2BPublicKeyRSA& rsa_proto,
                              std::vector<uint8_t>* buf, size_t& offset) {
  TPM2B_PUBLIC_KEY_RSA cipher = {};
  FillTpm2b(rsa_proto.buffer(), &cipher);
  return !MUCommandFailed(Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Marshal(
      &cipher, buf->data(), buf->size(), &offset));
}

bool MarshalTPMTRSADecrypt(const tpm_types::TPMTRSADecrypt& scheme_proto,
                           std::vector<uint8_t>* buf, size_t& offset) {
  const auto scheme = static_cast<uint16_t>(scheme_proto.scheme());
  if (MUCommandFailed(
          Tss2_MU_UINT16_Marshal(scheme, buf->data(), buf->size(), &offset)))
    return false;
  // hashAlg field is only marshaled for OAEP (TPM2_ALG_OAEP = 0x0017).
  if (scheme == TPM2_ALG_OAEP) {
    const auto hash_alg = static_cast<uint16_t>(scheme_proto.hash_alg());
    if (MUCommandFailed(Tss2_MU_UINT16_Marshal(hash_alg, buf->data(),
                                               buf->size(), &offset)))
      return false;
  }
  return true;
}

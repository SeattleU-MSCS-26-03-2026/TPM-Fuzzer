#include "harness/proto_normalization.h"

#include <string>

#include "constants/tpm_alg.pb.h"
#include "constants/tpm_cc.pb.h"
#include "constants/tpm_rh.pb.h"
#include "constants/tpm_st.pb.h"
#include "tpm_commands/tpm_clear.pb.h"
#include "tpm_commands/tpm_load.pb.h"
#include "tpm_commands/tpm_setprimarypolicy.pb.h"
#include "tpm_commands/tpm_startauthsession.pb.h"

namespace {
constexpr uint32_t kFirstHmacSessionHandle = 0x02000000;
constexpr uint32_t kPasswordSessionHandle = 0x40000009;
constexpr uint32_t kFirstTransientObjectHandle = 0x80000000;

constexpr uint32_t kAttrFixedTpm = 0x00000002;
constexpr uint32_t kAttrFixedParent = 0x00000010;
constexpr uint32_t kAttrSensitiveDataOrigin = 0x00000020;
constexpr uint32_t kAttrUserWithAuth = 0x00000040;
constexpr uint32_t kAttrNoDa = 0x00000400;
constexpr uint32_t kAttrRestricted = 0x00010000;
constexpr uint32_t kAttrDecrypt = 0x00020000;

constexpr uint32_t kStorageParentObjectAttributes =
    kAttrFixedTpm | kAttrFixedParent | kAttrSensitiveDataOrigin |
    kAttrUserWithAuth | kAttrNoDa | kAttrRestricted | kAttrDecrypt;
constexpr uint32_t kChildObjectAttributes =
    kAttrFixedTpm | kAttrFixedParent | kAttrSensitiveDataOrigin |
    kAttrUserWithAuth | kAttrNoDa | kAttrRestricted | kAttrDecrypt;
}  // namespace

void SetHmacSession(tpm_types::TPMSession* session, char nonce_fill) {
  session->set_session_handle(kFirstHmacSessionHandle);
  session->set_nonce(std::string(16, nonce_fill));
  session->set_nonce_size(16);
  session->set_session_attributes(0);
  session->set_hmac("");
  session->set_hmac_size(0);
}

void SetPasswordSession(tpm_types::TPMSession* session) {
  session->set_session_handle(kPasswordSessionHandle);
  session->set_nonce_size(0);
  session->set_session_attributes(0);
  session->set_hmac_size(0);
}

void NormalizeRsaOrKeyedHashPublic(tpm_types::TPMTPublic* public_area,
                                   uint32_t object_attributes) {
  auto* parameters = public_area->mutable_parameters();
  if (!parameters->has_rsa() && !parameters->has_keyedhash()) {
    public_area->set_type(constants::TPM_ALG_KEYEDHASH);
    auto* keyedhash = parameters->mutable_keyedhash();
    if (keyedhash->scheme() == constants::TPM_ALG_UNSPECIFIED)
      keyedhash->set_scheme(constants::TPM_ALG_NULL);
  } else if (parameters->has_keyedhash()) {
    public_area->set_type(constants::TPM_ALG_KEYEDHASH);
    auto* keyedhash = parameters->mutable_keyedhash();
    if (keyedhash->scheme() == constants::TPM_ALG_UNSPECIFIED)
      keyedhash->set_scheme(constants::TPM_ALG_NULL);
  } else if (parameters->has_rsa()) {
    public_area->set_type(constants::TPM_ALG_RSA);
    auto* rsa = parameters->mutable_rsa();
    if (rsa->symmetric() == constants::TPM_ALG_UNSPECIFIED)
      rsa->set_symmetric(constants::TPM_ALG_AES);
    if (rsa->symmetric_key_bits() == 0) rsa->set_symmetric_key_bits(128);
    if (rsa->scheme() == constants::TPM_ALG_UNSPECIFIED)
      rsa->set_scheme(constants::TPM_ALG_NULL);
    if (rsa->key_bits() == 0) rsa->set_key_bits(2048);
    if (rsa->exponent() == 0) rsa->set_exponent(0);
  } else {
    public_area->set_type(constants::TPM_ALG_KEYEDHASH);
  }

  if (public_area->name_alg() == constants::TPM_ALG_UNSPECIFIED)
    public_area->set_name_alg(constants::TPM_ALG_SHA256);
  if (public_area->object_attributes() == 0)
    public_area->set_object_attributes(object_attributes);
}

void NormalizeInPublic(tpm_commands::TPMLoad* msg) {
  if (msg->has_in_public()) {
    NormalizeRsaOrKeyedHashPublic(
        msg->mutable_in_public()->mutable_public_area(),
        kChildObjectAttributes);
  }
}

void NormalizeLoad(tpm_commands::TPMLoad* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_LOAD);

  if (msg->parent_handle() == 0) {
    msg->set_parent_handle(kFirstTransientObjectHandle);
  }

  if (msg->sessions().empty()) {
    SetPasswordSession(msg->add_sessions());
  }
}

void NormalizeCreatePrimary(tpm_commands::TPMCreatePrimary* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_CREATE_PRIMARY);

  if (msg->hierarchy() == constants::TPM_RH_UNSPECIFIED)
    msg->set_hierarchy(constants::TPM_RH_OWNER);

  NormalizeRsaOrKeyedHashPublic(msg->mutable_in_public()->mutable_public_area(),
                                kStorageParentObjectAttributes);
}

void NormalizeCreate(tpm_commands::TPMCreate* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_CREATE);

  if (msg->parent_handle() == 0) {
    msg->set_parent_handle(kFirstTransientObjectHandle);
  }

  NormalizeRsaOrKeyedHashPublic(msg->mutable_in_public()->mutable_public_area(),
                                kChildObjectAttributes);
}

void NormalizeRSADecrypt(tpm_commands::TPMRSADecrypt* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_RSA_DECRYPT);
}

void NormalizeClear(tpm_commands::TPMClear* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_CLEAR);

  if (msg->auth_handle() == 0) {
    msg->set_auth_handle(constants::TPM_RH_LOCKOUT);
  }

  if (msg->sessions().empty()) {
    SetPasswordSession(msg->add_sessions());
  }
}

void NormalizeSetPrimaryPolicy(tpm_commands::TPMSetPrimaryPolicy* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_SET_PRIMARY_POLICY);

  if (msg->auth_handle() == constants::TPM_RH_UNSPECIFIED) {
    msg->set_auth_handle(constants::TPM_RH_OWNER);
  }

  if (msg->sessions().empty()) {
    SetPasswordSession(msg->add_sessions());
  }

  // Keep auth_policy size consistent with hash_alg for valid paths.
  // This helps the fuzzer reach the switch(authHandle) cases in
  // SetPrimaryPolicy.c.
  switch (msg->hash_alg()) {
    case constants::TPM_ALG_SHA1:
      msg->mutable_auth_policy()->set_size(20);
      if (msg->auth_policy().buffer().size() != 20) {
        msg->mutable_auth_policy()->set_buffer(std::string(20, '\0'));
      }
      break;

    case constants::TPM_ALG_SHA256:
      msg->mutable_auth_policy()->set_size(32);
      if (msg->auth_policy().buffer().size() != 32) {
        msg->mutable_auth_policy()->set_buffer(std::string(32, '\0'));
      }
      break;

    case constants::TPM_ALG_SHA384:
      msg->mutable_auth_policy()->set_size(48);
      if (msg->auth_policy().buffer().size() != 48) {
        msg->mutable_auth_policy()->set_buffer(std::string(48, '\0'));
      }
      break;

    case constants::TPM_ALG_NULL:
      msg->mutable_auth_policy()->set_size(0);
      msg->mutable_auth_policy()->set_buffer("");
      break;

    default:
      msg->set_hash_alg(constants::TPM_ALG_SHA256);
      msg->mutable_auth_policy()->set_size(32);
      msg->mutable_auth_policy()->set_buffer(std::string(32, '\0'));
      break;
  }
}
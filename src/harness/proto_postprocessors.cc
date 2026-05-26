#include "harness/proto_postprocessors.h"

#include "constants/tpm_cc.pb.h"
#include "constants/tpm_st.pb.h"
#include "harness/proto_normalization.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"
#include "tpm_commands/tpm_clear.pb.h"
#include "tpm_commands/tpm_nv_definespace.pb.h"
#include "tpm_commands/tpm_pcr_event.pb.h"
#include "tpm_commands/tpm_rsa_decrypt.pb.h"
#include "tpm_commands/tpm_rsa_encrypt.pb.h"

namespace {
void NormalizeStartAuthSession(tpm_commands::TPMStartAuthSession* msg) {
  msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
  msg->mutable_header()->set_command_code(constants::TPM_CC_START_AUTH_SESSION);

  if (msg->tpm_key() == constants::TPM_RH_UNSPECIFIED)
    msg->set_tpm_key(constants::TPM_RH_NULL);
  if (msg->bind() == constants::TPM_RH_UNSPECIFIED)
    msg->set_bind(constants::TPM_RH_NULL);
  if (msg->session_type() == constants::TPM_SE_HMAC &&
      msg->auth_hash() == constants::TPM_ALG_UNSPECIFIED)
    msg->set_auth_hash(constants::TPM_ALG_SHA256);
  if (msg->auth_hash() == constants::TPM_ALG_UNSPECIFIED)
    msg->set_auth_hash(constants::TPM_ALG_SHA256);

  if (msg->symmetric().algorithm() == constants::TPM_ALG_UNSPECIFIED)
    msg->mutable_symmetric()->set_algorithm(constants::TPM_ALG_NULL);

  if (msg->nonce().buffer().empty()) {
    msg->mutable_nonce()->set_buffer(std::string(16, '\0'));
  }
}

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMClear>
    reg_clear = {[](tpm_commands::TPMClear* msg, unsigned int /* seed */) {
      NormalizeClear(msg);
    }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMPCRAllocate>
    reg_pcr_allocate = {[](tpm_commands::TPMPCRAllocate* msg,
                           unsigned int /* seed */) {
      msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
      msg->mutable_header()->set_command_code(constants::TPM_CC_PCR_ALLOCATE);
    }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMGetRandom>
    reg_getrandom = {
        [](tpm_commands::TPMGetRandom* msg, unsigned int /* seed */) {
          msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
          msg->mutable_header()->set_command_code(constants::TPM_CC_GET_RANDOM);
          msg->mutable_header()->set_command_size(12);

          if (msg->bytes_requested() == 0) msg->set_bytes_requested(1);
        }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMStartAuthSession>
    reg_startauth = {
        [](tpm_commands::TPMStartAuthSession* msg, unsigned int /* seed */) {
          NormalizeStartAuthSession(msg);
        }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMCreatePrimary>
    reg_createprimary = {
        [](tpm_commands::TPMCreatePrimary* msg, unsigned int /* seed */) {
          NormalizeCreatePrimary(msg);
        }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMCreate>
    reg_create = {[](tpm_commands::TPMCreate* msg, unsigned int /* seed */) {
      NormalizeCreate(msg);
    }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMRSADecrypt>
    reg_rsadecrypt = {
        [](tpm_commands::TPMRSADecrypt* msg, unsigned int /* seed */) {
          NormalizeRSADecrypt(msg);
        }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMRSAEncrypt>
    reg_rsaencrypt = {[](tpm_commands::TPMRSAEncrypt* msg,
                         unsigned int /* seed */) {
      msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
      msg->mutable_header()->set_command_code(constants::TPM_CC_RSA_ENCRYPT);
    }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMPCREvent>
    reg_pcr_event = {
        [](tpm_commands::TPMPCREvent* msg, unsigned int /* seed */) {
          msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
          msg->mutable_header()->set_command_code(constants::TPM_CC_PCR_EVENT);
        }};

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMNvDefineSpace>
    reg_nvdefinespace = {
        [](tpm_commands::TPMNvDefineSpace* msg, unsigned int /* seed */) {
          msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
          msg->mutable_header()->set_command_code(
              constants::TPM_CC_NV_DEFINE_SPACE);
        }};

}  // namespace

bool RegisterPostProcessors() { return true; }

#include "harness/proto_postprocessors.h"

#include "harness/proto_normalization.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"

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
    tpm::TPMCommandSequence>
    reg_sequence = {[](tpm::TPMCommandSequence* seq, unsigned int /* seed */) {
      NormalizeCommandSequence(seq);
    }};
}  // namespace

bool RegisterPostProcessors() { return true; }

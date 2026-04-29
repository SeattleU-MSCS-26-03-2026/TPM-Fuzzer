#include <cstdint>
#include <vector>

#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"

extern "C" {
#include <harness/tpm_wrapper.h>
}
#include "harness/proto_conversion.h"

constexpr uint32_t kFirstHmacSessionHandle = 0x02000000;
namespace {
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMGetRandom>
    reg = {[](tpm_commands::TPMGetRandom* msg, unsigned int /* seed */) {
      msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
      msg->mutable_header()->set_command_code(constants::TPM_CC_GET_RANDOM);
      msg->mutable_header()->set_command_size(12);

      if (msg->bytes_requested() == 0) msg->set_bytes_requested(1);
    }};

// ── StartAuthSession PostProcessor ───────────────────────────────────────────
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMStartAuthSession>
    reg_startauth = {
        [](tpm_commands::TPMStartAuthSession* msg, unsigned int /* seed */) {
          msg->mutable_header()->set_tag(constants::TPM_ST_NO_SESSIONS);
          msg->mutable_header()->set_command_code(
              constants::TPM_CC_START_AUTH_SESSION);

          if (msg->tpm_key() == constants::TPM_RH_UNSPECIFIED)
            msg->set_tpm_key(constants::TPM_RH_NULL);
          if (msg->bind() == constants::TPM_RH_UNSPECIFIED)
            msg->set_bind(constants::TPM_RH_NULL);
          if (msg->session_type() == constants::TPM_SE_HMAC &&
              msg->auth_hash() == constants::TPM_ALG_UNSPECIFIED)
            msg->set_auth_hash(constants::TPM_ALG_SHA256);
          if (msg->auth_hash() == constants::TPM_ALG_UNSPECIFIED)
            msg->set_auth_hash(constants::TPM_ALG_SHA256);

          // Default symmetric to NULL if unset.
          if (msg->symmetric().algorithm() == constants::TPM_ALG_UNSPECIFIED)
            msg->mutable_symmetric()->set_algorithm(constants::TPM_ALG_NULL);

          // Provide a 16-byte zero nonce if none exists.
          if (msg->nonce().buffer().empty()) {
            msg->mutable_nonce()->set_buffer(std::string(16, '\0'));
          }
        }};

// ── CreatePrimary PostProcessor ──────────────────────────────────────────────
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm_commands::TPMCreatePrimary>
    reg_createprimary = {[](tpm_commands::TPMCreatePrimary* msg,
                            unsigned int /* seed */) {
      msg->mutable_header()->set_tag(constants::TPM_ST_SESSIONS);
      msg->mutable_header()->set_command_code(constants::TPM_CC_CREATE_PRIMARY);

      if (msg->hierarchy() == constants::TPM_RH_UNSPECIFIED)
        msg->set_hierarchy(constants::TPM_RH_OWNER);

      // Tss2_MU_TPM2B_PUBLIC_Marshal requires the public area type and
      // parms oneof to be mutually consistent.  The valid public area
      // tpm_types supported by our proto are RSA and KEYEDHASH.  Enforce
      // whichever was chosen by the fuzzer, defaulting to RSA.
      auto* pa = msg->mutable_in_public()->mutable_public_area();
      auto* parms = pa->mutable_parameters();

      if (parms->has_keyedhash()) {
        pa->set_type(constants::TPM_ALG_KEYEDHASH);
        auto* kh = parms->mutable_keyedhash();
        if (kh->scheme() == constants::TPM_ALG_UNSPECIFIED)
          kh->set_scheme(constants::TPM_ALG_NULL);
      } else {
        // RSA case (or neither parms set — default to RSA).
        pa->set_type(constants::TPM_ALG_RSA);
        auto* rsa = parms->mutable_rsa();
        // symmetric.algorithm must not be 0 — default to NULL (no cipher).
        if (rsa->symmetric() == constants::TPM_ALG_UNSPECIFIED)
          rsa->set_symmetric(constants::TPM_ALG_NULL);
        // scheme must not be 0 — default to NULL (no signing/encrypt scheme).
        if (rsa->scheme() == constants::TPM_ALG_UNSPECIFIED)
          rsa->set_scheme(constants::TPM_ALG_NULL);
      }

      if (pa->name_alg() == constants::TPM_ALG_UNSPECIFIED)
        pa->set_name_alg(constants::TPM_ALG_SHA256);
    }};

// ── Sequence PostProcessor: coordinate StartAuthSession + CreatePrimary ──────
static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    tpm::TPMCommandSequence>
    reg_sequence = {[](tpm::TPMCommandSequence* seq, unsigned int /* seed */) {
      // Find the first CreatePrimary command.
      int create_primary_index = -1;
      for (int i = 0; i < seq->commands_size(); ++i) {
        if (seq->commands(i).has_createprimary()) {
          create_primary_index = i;
          break;
        }
      }
      if (create_primary_index == -1) return;

      // Check if a StartAuthSession already exists before it.
      bool has_start_auth = false;
      for (int i = 0; i < create_primary_index; ++i) {
        if (seq->commands(i).has_startauthsession()) {
          has_start_auth = true;
          break;
        }
      }

      if (!has_start_auth) {
        // Append a StartAuthSession command, then swap it into position
        // just before CreatePrimary.
        tpm::TPMCommand* new_cmd = seq->add_commands();
        new_cmd->mutable_startauthsession();

        // Swap from the end to just before create_primary_index.
        int last = seq->commands_size() - 1;
        for (int i = last; i > create_primary_index; --i) {
          seq->mutable_commands()->SwapElements(i, i - 1);
        }
        // CreatePrimary is now at create_primary_index + 1.
        create_primary_index += 1;
      }

      // Ensure CreatePrimary has at least one session referencing the
      // first HMAC session handle.
      tpm_commands::TPMCreatePrimary* cp =
          seq->mutable_commands(create_primary_index)->mutable_createprimary();
      if (cp->sessions_size() == 0) {
        tpm_types::TPMSession* session = cp->add_sessions();
        session->set_session_handle(kFirstHmacSessionHandle);
        session->set_nonce_size(0);
        session->set_session_attributes(0);
        session->set_hmac_size(0);
      }
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

  TPMSendCommand(kDefaultLocality, request, &response);
}
}  // namespace

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) {
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();

  std::vector<uint8_t> command_buffer;
  std::vector<uint8_t> response_storage(kMaxBuffers);

  for (const auto& cmd : sequence.commands()) {
    if (!MarshalCommand(cmd, &command_buffer)) {
      continue;
    }
    ExecuteCommandBuffer(command_buffer, &response_storage);
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();
}

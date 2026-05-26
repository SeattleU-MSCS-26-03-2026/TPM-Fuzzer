#ifndef FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_
#define FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_

#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

// Minimal per-command attribute lookup used by the HMAC Auth Layer to parse
// command/response wire buffers. The TPM reference implementation keeps its
// COMMAND_ATTRIBUTES table in a private header (vendor/TPM/.../private/
// CommandAttributeData.h) that the harness cannot link against, and tpm2-tss
// does not export an equivalent in its public headers. This lookup covers the
// commands the proto fuzzer currently emits.
struct CommandAttrEntry {
  uint32_t command_code;
  uint8_t handle_count;       // total handles in the handle area (0..3)
  uint8_t auth_handle_count;  // subset of handles requiring authorization
  uint8_t out_handle_count;   // handles returned in the response handle area
};

// Returns true if the command is known and fills *out. Returns false otherwise.
inline bool LookupCommandAttr(uint32_t command_code, CommandAttrEntry* out) {
  // Per-command handle counts cribbed from TPM 2.0 Part 3 (Commands).
  // Fields: command_code | handle_count | auth_handle_count | out_handle_count
  // handle_count: total handles in the command handle area
  // auth_handle_count: subset of those requiring an authorization session entry
  // out_handle_count: handles returned in the response handle area
  static constexpr CommandAttrEntry kTable[] = {
      // commandCode                  in  auth  out
      {TPM2_CC_Clear, 1, 1, 0},
      {TPM2_CC_CreatePrimary, 1, 1, 1},
      {TPM2_CC_ActivateCredential, 2, 2, 0},
      {TPM2_CC_Create, 1, 1, 0},
      {TPM2_CC_Load, 1, 1, 1},
      {TPM2_CC_Quote, 1, 1, 0},
      {TPM2_CC_RSA_Decrypt, 1, 1, 0},
      {TPM2_CC_Sign, 1, 1, 0},
      {TPM2_CC_Unseal, 1, 1, 0},
      {TPM2_CC_ContextLoad, 0, 0, 1},
      {TPM2_CC_ContextSave, 1, 0, 0},
      {TPM2_CC_FlushContext, 0, 0, 0},
      {TPM2_CC_MakeCredential, 1, 0, 0},
      {TPM2_CC_StartAuthSession, 2, 0, 1},
      {TPM2_CC_VerifySignature, 1, 0, 0},
      {TPM2_CC_GetCapability, 0, 0, 0},
      {TPM2_CC_GetRandom, 0, 0, 0},
      {TPM2_CC_PCR_Extend, 1, 1, 0},
      {TPM2_CC_NV_DefineSpace, 1, 1, 0},
  };

  for (size_t i = 0; i < sizeof(kTable) / sizeof(kTable[0]); ++i) {
    if (kTable[i].command_code == command_code) {
      if (out) *out = kTable[i];
      return true;
    }
  }
  return false;
}

#endif  // FUZZER_HARNESS_COMMAND_ATTRIBUTES_H_

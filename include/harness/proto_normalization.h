#ifndef HARNESS_PROTO_NORMALIZATION_H_
#define HARNESS_PROTO_NORMALIZATION_H_

// Normalizer helpers shared by PostProcessor registrations in
// proto_postprocessors.cc.  Per-command normalizers that don't need shared
// helpers are defined as static functions there and not declared here.

#include <cstdint>

#include "tpm_commands.pb.h"
#include "tpm_commands/tpm_clear.pb.h"
#include "tpm_commands/tpm_create.pb.h"
#include "tpm_commands/tpm_createprimary.pb.h"
#include "tpm_commands/tpm_load.pb.h"
#include "tpm_commands/tpm_nv_definespace.pb.h"
#include "tpm_commands/tpm_rsa_decrypt.pb.h"
#include "tpm_commands/tpm_setprimarypolicy.pb.h"
#include "tpm_types/tpm2b_public.pb.h"
#include "tpm_types/tpm_session.pb.h"

void SetHmacSession(tpm_types::TPMSession* session, char nonce_fill);

void SetPasswordSession(tpm_types::TPMSession* session);

void NormalizeRsaOrKeyedHashPublic(tpm_types::TPMTPublic* public_area,
                                   uint32_t object_attributes);

void NormalizeCreatePrimary(tpm_commands::TPMCreatePrimary* msg);

void NormalizeClear(tpm_commands::TPMClear* msg);

void NormalizeSetPrimaryPolicy(tpm_commands::TPMSetPrimaryPolicy* msg);

void NormalizeCreate(tpm_commands::TPMCreate* msg);

void NormalizeRSADecrypt(tpm_commands::TPMRSADecrypt* msg);

void NormalizeCommandSequence(tpm::TPMCommandSequence* seq);

void NormalizeLoad(tpm_commands::TPMLoad* msg);

void NormalizeInPublic(tpm_commands::TPMLoad* msg);

#endif  // HARNESS_PROTO_NORMALIZATION_H_

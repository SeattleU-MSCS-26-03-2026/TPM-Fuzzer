#ifndef FUZZER_HARNESS_SESSION_AUTH_H_
#define FUZZER_HARNESS_SESSION_AUTH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Max digest size (SHA-512).
#define SESSION_AUTH_MAX_DIGEST 64

// Reactive session auth layer. Self-bootstraps when the seed sends a
// TPM2_StartAuthSession; pipe every command through PatchCommand before
// sending and every response through ProcessResponse after receiving.
// Currently only HMAC sessions (null salt, no bind) are armed; other
// session types pass through unmodified.

// Arm the layer directly. Called internally; exposed for tests.
void SessionAuthInit(uint32_t session_handle, const uint8_t* nonce_tpm,
                     size_t nonce_tpm_size, const uint8_t* session_key,
                     size_t session_key_size, uint16_t auth_hash_alg);

// Clear all state. Call at the start of every fuzz iteration.
void SessionAuthReset(void);

// Active session handle, or 0 if none.
uint32_t SessionAuthGetSessionHandle(void);

// Patch nonceCaller + HMAC into a session-tagged command, or capture
// StartAuthSession parameters off the wire. Needs ~64 bytes of headroom.
// Returns the new command size (== command_size when nothing is patched).
size_t SessionAuthPatchCommand(uint8_t* buf, size_t command_size,
                               size_t buf_capacity);

// Arm the layer from a StartAuthSession response, refresh nonceTPM, and
// record output handle Names for tracked commands.
void SessionAuthProcessResponse(const uint8_t* response_buf,
                                size_t response_size);

#ifdef __cplusplus
}
#endif

#endif  // FUZZER_HARNESS_SESSION_AUTH_H_

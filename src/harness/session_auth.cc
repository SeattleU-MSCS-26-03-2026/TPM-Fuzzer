#include "harness/session_auth.h"

// SHA256_Init/Update/Final and HMAC are deprecated in OpenSSL 3 in favor of
// the EVP_* API; the project still links libcrypto from OpenSSL 1.1+/3.x and
// the legacy entry points remain available, so silence the diagnostic locally
// rather than refactor for the smaller, simpler interface.
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>

#include "harness/command_attributes.h"

namespace {

// cpHash = H(commandCode || Name(h0) || ... || cpBuffer)  (Part 3 §18.6.6)
// HMAC   = HMAC_SHA256(sessionKey||authValue,
// cpHash||nonceCaller||nonceTPM||attrs)
//          (Part 1 §19.6.5; both keys are empty for null-salt no-bind sessions)

// Fixed nonceCaller used for every HMAC-authorized command. The TPM accepts
// any 16+ byte nonce; we keep this constant so the HMAC is reproducible across
// runs given the same fuzzed parameters.
constexpr uint8_t kNonceCallerFill = 0xAA;
constexpr size_t kNonceCallerSize = 16;

// Maximum number of transient/persistent handles whose Names we track.
constexpr int kMaxNames = 16;
// algId(2) + SHA-512 digest(64) = 66; round up to 68.
constexpr size_t kMaxNameSize = 68;

// ── data structures and session state ─────────────────────────────────────

struct NameEntry {
  uint32_t handle;
  uint8_t name[kMaxNameSize];
  size_t name_size;
};

// Tracks handle→Name mappings for transient and persistent objects.
struct NameTable {
  NameEntry entries[kMaxNames];
  int count;

  // Store (or update) a handle→Name mapping.
  void Add(uint32_t handle, const uint8_t* name, size_t name_size) {
    if (name_size > kMaxNameSize) name_size = kMaxNameSize;
    for (int i = 0; i < count; ++i) {
      if (entries[i].handle == handle) {
        std::memcpy(entries[i].name, name, name_size);
        entries[i].name_size = name_size;
        return;
      }
    }
    if (count < kMaxNames) {
      NameEntry& e = entries[count++];
      e.handle = handle;
      std::memcpy(e.name, name, name_size);
      e.name_size = name_size;
    }
  }

  // Returns the Name for a transient (0x80) or persistent (0x81) handle,
  // or 0 if not found.
  size_t Lookup(uint32_t handle, uint8_t* name_out, size_t name_cap) const {
    for (int i = 0; i < count; ++i) {
      if (entries[i].handle == handle) {
        size_t ns = entries[i].name_size;
        if (ns > name_cap) return 0;
        std::memcpy(name_out, entries[i].name, ns);
        return ns;
      }
    }
    return 0;
  }
};

struct SessionState {
  bool initialized;
  uint32_t handle;
  uint16_t hash_alg;
  size_t digest_size;
  uint8_t nonce_tpm[SESSION_AUTH_MAX_DIGEST];
  size_t nonce_tpm_size;
  uint8_t session_key[SESSION_AUTH_MAX_DIGEST];
  size_t session_key_size;
  uint32_t last_command_code;
  NameTable names;

  // Reactive StartAuthSession bookkeeping. PatchCommand sets these when it
  // sees a TPM2_StartAuthSession on the wire; ProcessResponse consumes them
  // when the matching response arrives, then resets pending.
  bool pending_start_auth_session;
  bool start_auth_session_compatible;  // null salt + no bind + supported hash
  uint16_t start_auth_session_auth_hash;
};

SessionState g_session = {};

// ── byte and algorithm utilities ───────────────────────────────────────────

inline uint16_t Read16(const uint8_t* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t Read32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void Write16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

inline void Write32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

// Phase 1: only SHA-256 is supported. Returns 0 for unsupported algs so callers
// can early-out cleanly (the TPM will then see whatever was originally
// written).
size_t DigestSizeFor(uint16_t alg) { return alg == TPM2_ALG_SHA256 ? 32 : 0; }

// ── crypto primitives ──────────────────────────────────────────────────────

// HMAC-SHA256 with caller-provided key (zero-length keys are valid per the
// TPM 2.0 spec for empty sessionKey/authValue).
void HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* msg,
                size_t msg_len, uint8_t out[32]) {
  unsigned int out_len = 32;
  HMAC(EVP_sha256(), key, static_cast<int>(key_len), msg, msg_len, out,
       &out_len);
}

// ── handle Name resolution ─────────────────────────────────────────────────

// Advance past a TPM2B field (2-byte size prefix + payload). Returns the new
// offset, or 0 on parse error. Callers can use 0 as an error sentinel because
// all legitimate offsets in a response buffer are well past position 0.
size_t SkipTPM2B(const uint8_t* buf, size_t off, size_t end) {
  if (off + 2 > end) return 0;
  const uint16_t sz = Read16(buf + off);
  const size_t new_off = off + 2u + sz;
  return (new_off <= end) ? new_off : 0u;
}

// Returns the wire-format Name for a handle.
// Permanent/PCR/session handles: raw 4-byte value.  Transient/persistent:
// looked up in the Name table; returns 0 if not yet populated (command is
// left unpatched and the TPM will reject at auth).
size_t HandleName(uint32_t handle, uint8_t* name_out, size_t name_cap) {
  uint8_t handle_type = static_cast<uint8_t>(handle >> 24);

  // Transient and persistent: look up in Name table.
  if (handle_type == 0x80 || handle_type == 0x81) {
    return g_session.names.Lookup(handle, name_out, name_cap);
  }

  // Permanent handle: 0x40xxxxxx
  if (handle_type == 0x40) {
    if (name_cap < 4) return 0;
    Write32(name_out, handle);
    return 4;
  }

  // PCR (0x00) and HMAC/Policy/Active session (0x02/0x03): raw handle value.
  if (handle_type == 0x00 || handle_type == 0x02 || handle_type == 0x03) {
    if (name_cap < 4) return 0;
    Write32(name_out, handle);
    return 4;
  }

  return 0;
}

// ── Name extraction from responses ────────────────────────────────────────

// Parse CreatePrimary response parameters to extract the object Name.
// Response params layout (Part 3 §24.1):
//   outPublic (TPM2B) | creationData (TPM2B) | creationHash (TPM2B) |
//   creationTicket (TPMT_TK_CREATION: tag[2]+hierarchy[4]+digest[TPM2B]) |
//   name (TPM2B_NAME)
void ExtractCreatePrimaryName(const uint8_t* buf, size_t params_start,
                              size_t params_end, uint32_t out_handle) {
  size_t p = params_start;
  p = SkipTPM2B(buf, p, params_end);  // outPublic
  if (p == 0) return;
  p = SkipTPM2B(buf, p, params_end);  // creationData
  if (p == 0) return;
  p = SkipTPM2B(buf, p, params_end);  // creationHash
  if (p == 0) return;
  // creationTicket: tag(2) + hierarchy(4) + digest(TPM2B)
  if (p + 6 > params_end) return;
  p += 6;
  p = SkipTPM2B(buf, p, params_end);  // ticket digest
  if (p == 0) return;
  // name
  if (p + 2 > params_end) return;
  const uint16_t name_size = Read16(buf + p);
  if (p + 2u + name_size > params_end) return;
  g_session.names.Add(out_handle, buf + p + 2, name_size);
}

// Parse Load response parameters to extract the object Name.
// Response params layout (Part 3 §12.2): name (TPM2B_NAME) only.
void ExtractLoadName(const uint8_t* buf, size_t params_start, size_t params_end,
                     uint32_t out_handle) {
  if (params_start + 2 > params_end) return;
  const uint16_t name_size = Read16(buf + params_start);
  if (params_start + 2u + name_size > params_end) return;
  g_session.names.Add(out_handle, buf + params_start + 2, name_size);
}

// Dispatch table for commands that return a new transient handle whose Name
// must be recorded. To add a command: write ExtractXxxName() above and add
// an entry here.
typedef void (*NameExtractorFn)(const uint8_t* buf, size_t params_start,
                                size_t params_end, uint32_t out_handle);

struct NameExtractorEntry {
  uint32_t command_code;
  NameExtractorFn fn;
};

const NameExtractorEntry kNameExtractors[] = {
    {TPM2_CC_CreatePrimary, ExtractCreatePrimaryName},
    {TPM2_CC_Load, ExtractLoadName},
};

// Calls the registered extractor for the given command code, if any.
void PopulateNameFromResponse(uint32_t command_code, const uint8_t* buf,
                              size_t params_off, size_t params_end,
                              uint32_t out_handle) {
  for (size_t i = 0; i < sizeof(kNameExtractors) / sizeof(kNameExtractors[0]);
       ++i) {
    if (kNameExtractors[i].command_code == command_code) {
      kNameExtractors[i].fn(buf, params_off, params_end, out_handle);
      return;
    }
  }
}

// ── StartAuthSession helpers ──────────────────────────────────────

// Capture the StartAuthSession parameters off the command wire so the
// matching response handler knows whether to arm the session.
// Command layout:
//   header(10) | tpmKey(4) | bind(4) | nonceCaller(TPM2B) |
//   encryptedSalt(TPM2B) | sessionType(1) | symmetric(TPMT_SYM_DEF) |
//   authHash(2)
// authHash is the last 2 bytes regardless of how the symmetric field is
// encoded, so we read it from the tail and avoid parsing TPMT_SYM_DEF.
void CaptureStartAuthSessionCommand(const uint8_t* buf, size_t size) {
  g_session.pending_start_auth_session = true;
  g_session.start_auth_session_compatible = false;
  // header(10) + tpmKey(4) + bind(4) + nonceCaller size(2) +
  // encryptedSalt size(2) + sessionType(1) + symmetric.alg(2) + authHash(2)
  // = 27 bytes minimum.
  if (size < 27) return;

  size_t p = 10;
  const uint32_t tpm_key = Read32(buf + p);
  p += 4;
  const uint32_t bind = Read32(buf + p);
  p += 4;
  p = SkipTPM2B(buf, p, size);  // nonceCaller
  if (p == 0) return;
  const size_t encrypted_salt_off = p;
  p = SkipTPM2B(buf, p, size);  // encryptedSalt
  if (p == 0) return;
  if (p + 1 > size) return;
  const uint8_t session_type = buf[p];

  const uint16_t auth_hash = Read16(buf + size - 2);
  const uint16_t encrypted_salt_size = Read16(buf + encrypted_salt_off);

  g_session.start_auth_session_auth_hash = auth_hash;
  g_session.start_auth_session_compatible =
      tpm_key == TPM2_RH_NULL && bind == TPM2_RH_NULL &&
      encrypted_salt_size == 0 && session_type == TPM2_SE_HMAC &&
      DigestSizeFor(auth_hash) != 0;
}

// ── command patching pipeline ──────────────────────────────────────────────

// Locates and validates the authorization area in a command buffer.
// Populates auth_size_off, auth_off, and auth_size on success.
bool FindAuthArea(const uint8_t* buf, size_t command_size,
                  const CommandAttrEntry& attr, size_t* auth_size_off_out,
                  size_t* auth_off_out, uint32_t* auth_size_out) {
  const size_t handles_off = 10;
  const size_t auth_size_off = handles_off + 4u * attr.handle_count;
  if (auth_size_off + 4 > command_size) return false;

  const uint32_t auth_size = Read32(buf + auth_size_off);
  const size_t auth_off = auth_size_off + 4;
  if (auth_off + auth_size > command_size) return false;

  *auth_size_off_out = auth_size_off;
  *auth_off_out = auth_off;
  *auth_size_out = auth_size;
  return true;
}

// Builds cpHash = H(commandCode || Name(h0) || ... || cpBuffer).
// Per ComputeCpHash in vendor/TPM/.../main/SessionProcess.c, the Names of
// ALL handles in the handle area are included, not just authorization handles.
// Returns false if any handle Name lookup fails.
bool ComputeCpHash(const uint8_t* buf, uint32_t command_code,
                   uint8_t handle_count, size_t cp_off, size_t cp_size,
                   uint8_t cp_hash_out[32]) {
  // Handles start at byte 10 in every TPM 2.0 command (Part 1 §18.5).
  constexpr size_t kHandlesOff = 10;
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  uint8_t cc_be[4];
  Write32(cc_be, command_code);
  SHA256_Update(&ctx, cc_be, 4);
  for (uint8_t i = 0; i < handle_count; ++i) {
    const uint32_t h = Read32(buf + kHandlesOff + 4u * i);
    uint8_t name[68];
    const size_t name_size = HandleName(h, name, sizeof(name));
    if (name_size == 0) return false;
    SHA256_Update(&ctx, name, name_size);
  }
  if (cp_size) SHA256_Update(&ctx, buf + cp_off, cp_size);
  SHA256_Final(cp_hash_out, &ctx);
  return true;
}

// Assembles the HMAC message and computes the HMAC-SHA256 result.
// hmacKey = sessionKey || authValue (both empty for null-salt no-bind
// sessions). nonceNewer = nonceCaller (we control); nonceOlder = nonceTPM
// (session state).
void ComputeHmac(const uint8_t cp_hash[32], const uint8_t* nonce_caller,
                 size_t nonce_caller_size, const uint8_t* nonce_tpm,
                 size_t nonce_tpm_size, uint8_t session_attrs,
                 const uint8_t* session_key, size_t session_key_size,
                 uint8_t hmac_out[32]) {
  // Build the HMAC message: cpHash || nonceNewer || nonceOlder || sessionAttrs
  uint8_t hmac_msg[32 + kNonceCallerSize + SESSION_AUTH_MAX_DIGEST + 1];
  size_t mlen = 0;
  std::memcpy(hmac_msg + mlen, cp_hash, 32);
  mlen += 32;
  std::memcpy(hmac_msg + mlen, nonce_caller, nonce_caller_size);
  mlen += nonce_caller_size;
  std::memcpy(hmac_msg + mlen, nonce_tpm, nonce_tpm_size);
  mlen += nonce_tpm_size;
  hmac_msg[mlen++] = session_attrs;

  // hmacKey = sessionKey || authValue (both empty for null-salt no-bind session
  // on a freshly manufactured TPM).
  uint8_t hmac_key[SESSION_AUTH_MAX_DIGEST];
  size_t hmac_key_len = 0;
  if (session_key_size) {
    std::memcpy(hmac_key, session_key, session_key_size);
    hmac_key_len = session_key_size;
  }
  HmacSha256(hmac_key, hmac_key_len, hmac_msg, mlen, hmac_out);
}

// Shifts cpBuffer, rewrites the nonce+HMAC in-place, and updates the
// authorizationSize and commandSize headers. Returns the new command size,
// or the original command_size if the buffer is too small.
size_t PatchAuthArea(uint8_t* buf, size_t buf_capacity, size_t command_size,
                     size_t nonce_off, uint16_t orig_nonce_size,
                     uint16_t orig_hmac_size, uint8_t session_attrs,
                     size_t auth_size_off, uint32_t auth_size,
                     const uint8_t* nonce_caller, size_t nonce_caller_size,
                     const uint8_t hmac_out[32]) {
  const size_t cp_off = auth_size_off + 4u + auth_size;
  const size_t cp_size = command_size - cp_off;

  const size_t new_nonce_field = 2 + nonce_caller_size;
  const size_t new_hmac_field = 2 + 32u;  // HMAC is always SHA-256 (32 bytes)
  const size_t old_nonce_field = 2 + orig_nonce_size;
  const size_t old_hmac_field = 2 + orig_hmac_size;
  const std::int64_t delta =
      static_cast<std::int64_t>(new_nonce_field + new_hmac_field) -
      static_cast<std::int64_t>(old_nonce_field + old_hmac_field);
  const size_t new_command_size =
      static_cast<size_t>(static_cast<std::int64_t>(command_size) + delta);
  if (new_command_size > buf_capacity) return command_size;

  // Shift cpBuffer to its new offset.
  const size_t new_cp_off =
      static_cast<size_t>(static_cast<std::int64_t>(cp_off) + delta);
  if (cp_size && new_cp_off != cp_off) {
    std::memmove(buf + new_cp_off, buf + cp_off, cp_size);
  }

  // Rewrite the auth area entry in place.
  size_t w = nonce_off;
  Write16(buf + w, static_cast<uint16_t>(nonce_caller_size));
  w += 2;
  std::memcpy(buf + w, nonce_caller, nonce_caller_size);
  w += nonce_caller_size;
  buf[w++] = session_attrs;
  Write16(buf + w, 32u);  // HMAC size
  w += 2;
  std::memcpy(buf + w, hmac_out, 32);
  w += 32;
  // Pad-zero any leftover bytes between the rewritten auth area and the moved
  // cpBuffer (only happens when the new auth area is smaller than the old,
  // which can't occur here since nonce/hmac always grow). Defensive only.
  while (w < new_cp_off) buf[w++] = 0;

  // Rewrite authorizationSize and commandSize headers.
  const uint32_t new_auth_size =
      static_cast<uint32_t>(static_cast<std::int64_t>(auth_size) + delta);
  Write32(buf + auth_size_off, new_auth_size);
  Write32(buf + 2, static_cast<uint32_t>(new_command_size));

  return new_command_size;
}

}  // namespace

extern "C" {

void SessionAuthInit(uint32_t session_handle, const uint8_t* nonce_tpm,
                     size_t nonce_tpm_size, const uint8_t* session_key,
                     size_t session_key_size, uint16_t auth_hash_alg) {
  std::memset(&g_session, 0, sizeof(g_session));
  g_session.initialized = true;
  g_session.handle = session_handle;
  g_session.hash_alg = auth_hash_alg;
  g_session.digest_size = DigestSizeFor(auth_hash_alg);

  if (nonce_tpm_size > sizeof(g_session.nonce_tpm)) {
    nonce_tpm_size = sizeof(g_session.nonce_tpm);
  }
  if (nonce_tpm && nonce_tpm_size) {
    std::memcpy(g_session.nonce_tpm, nonce_tpm, nonce_tpm_size);
  }
  g_session.nonce_tpm_size = nonce_tpm_size;

  if (session_key_size > sizeof(g_session.session_key)) {
    session_key_size = sizeof(g_session.session_key);
  }
  if (session_key && session_key_size) {
    std::memcpy(g_session.session_key, session_key, session_key_size);
  }
  g_session.session_key_size = session_key_size;
}

void SessionAuthReset(void) { std::memset(&g_session, 0, sizeof(g_session)); }

uint32_t SessionAuthGetSessionHandle(void) {
  return g_session.initialized ? g_session.handle : 0u;
}

size_t SessionAuthPatchCommand(uint8_t* buf, size_t command_size,
                               size_t buf_capacity) {
  if (!buf || command_size < 10 || command_size > buf_capacity) {
    return command_size;
  }

  const uint16_t tag = Read16(buf + 0);
  const uint32_t header_size = Read32(buf + 2);
  if (header_size != command_size) {
    // Marshaled header is inconsistent with the buffer -- bail and let the TPM
    // surface the issue.
    return command_size;
  }
  const uint32_t command_code = Read32(buf + 6);
  // Record which command is in-flight so SessionAuthProcessResponse can parse
  // the matching response layout (also covers the StartAuthSession before any
  // session is armed).
  g_session.last_command_code = command_code;

  // If the seed sends a TPM2_StartAuthSession, capture
  // its parameters off the wire so the response handler can arm the layer.
  if (command_code == TPM2_CC_StartAuthSession) {
    CaptureStartAuthSessionCommand(buf, command_size);
    return command_size;
  }

  if (!g_session.initialized || g_session.digest_size == 0) {
    return command_size;
  }
  if (tag != TPM2_ST_SESSIONS) {
    // Commands without sessions skip the auth layer entirely.
    return command_size;
  }

  CommandAttrEntry attr;
  if (!LookupCommandAttr(command_code, &attr)) {
    return command_size;
  }

  size_t auth_size_off, auth_off;
  uint32_t auth_size;
  if (!FindAuthArea(buf, command_size, attr, &auth_size_off, &auth_off,
                    &auth_size)) {
    return command_size;
  }

  // Parse the first auth area entry (HMAC session).
  // Multi-session commands carry additional entries after this one; password
  // sessions do not need an HMAC, so leaving them unchanged is correct.
  size_t p = auth_off;
  if (p + 4 > auth_off + auth_size) return command_size;
  const uint32_t session_handle = Read32(buf + p);
  p += 4;

  if (session_handle != g_session.handle) {
    // PW session, an unknown session handle, or one we haven't initialized.
    return command_size;
  }

  if (p + 2 > auth_off + auth_size) return command_size;
  const uint16_t orig_nonce_size = Read16(buf + p);
  const size_t nonce_off = p;
  p += 2 + orig_nonce_size;
  if (p + 1 > auth_off + auth_size) return command_size;
  const uint8_t session_attrs = buf[p];
  p += 1;
  if (p + 2 > auth_off + auth_size) return command_size;
  const uint16_t orig_hmac_size = Read16(buf + p);
  p += 2 + orig_hmac_size;
  if (p != auth_off + auth_size) return command_size;

  const size_t cp_off = auth_off + auth_size;
  const size_t cp_size = command_size - cp_off;

  uint8_t cp_hash[32];
  if (!ComputeCpHash(buf, command_code, attr.handle_count, cp_off, cp_size,
                     cp_hash)) {
    return command_size;  // Name not in table; let the TPM surface the auth
                          // error.
  }

  uint8_t nonce_caller[kNonceCallerSize];
  std::memset(nonce_caller, kNonceCallerFill, sizeof(nonce_caller));

  uint8_t hmac_out[32];
  ComputeHmac(cp_hash, nonce_caller, sizeof(nonce_caller), g_session.nonce_tpm,
              g_session.nonce_tpm_size, session_attrs, g_session.session_key,
              g_session.session_key_size, hmac_out);

  return PatchAuthArea(buf, buf_capacity, command_size, nonce_off,
                       orig_nonce_size, orig_hmac_size, session_attrs,
                       auth_size_off, auth_size, nonce_caller,
                       sizeof(nonce_caller), hmac_out);
}

void SessionAuthProcessResponse(const uint8_t* buf, size_t size) {
  if (!buf || size < 10) return;

  const uint16_t tag = Read16(buf + 0);
  const uint32_t hdr_size = Read32(buf + 2);
  const uint32_t rc = Read32(buf + 6);
  if (hdr_size != size) return;

  // Reactive bootstrap: a successful StartAuthSession response arms the layer.
  // Response layout (Part 3 §11.1):
  //   header(10) | sessionHandle(4) | nonceTPM(TPM2B)
  // This must run before the initialized check below since the layer is
  // not yet armed at this point.
  if (g_session.pending_start_auth_session) {
    const bool compatible = g_session.start_auth_session_compatible;
    const uint16_t auth_hash = g_session.start_auth_session_auth_hash;
    g_session.pending_start_auth_session = false;
    g_session.start_auth_session_compatible = false;
    if (tag != TPM2_ST_NO_SESSIONS || rc != TPM2_RC_SUCCESS) return;
    if (!compatible || size < 16) return;
    const uint32_t handle = Read32(buf + 10);
    const uint16_t nonce_size = Read16(buf + 14);
    if (16u + nonce_size > size) return;
    // null salt + no bind => sessionKey is empty (vendor/TPM/.../subsystem/
    // Session.c:476 only runs KDFa when bind != TPM_RH_NULL or seed.size != 0).
    SessionAuthInit(handle, buf + 16, nonce_size, /*session_key=*/nullptr,
                    /*session_key_size=*/0, auth_hash);
    return;
  }

  if (!g_session.initialized) return;
  if (tag != TPM2_ST_SESSIONS || rc != TPM2_RC_SUCCESS) return;

  // Look up command attributes to determine response layout.
  CommandAttrEntry attr;
  if (!LookupCommandAttr(g_session.last_command_code, &attr)) return;

  // Response layout (TPM_ST_SESSIONS, Part 2 §18.5):
  //   [0:1]   tag
  //   [2:5]   responseSize
  //   [6:9]   responseCode
  //   [10 .. 10+4*out_handle_count-1]  output handles (4 bytes each)
  //   [10+4*out_handle_count .. +3]    parameterSize (4 bytes)
  //   [params_off .. params_off+parameterSize-1]  parameters
  //   [auth_area_off ..]               response auth area
  const size_t params_size_off = 10u + 4u * attr.out_handle_count;
  if (params_size_off + 4 > size) return;

  const uint32_t param_size = Read32(buf + params_size_off);
  const size_t params_off = params_size_off + 4u;
  if (params_off + param_size > size) return;
  const size_t auth_area_off = params_off + param_size;

  // Response auth area entry: nonceTPM(TPM2B) | sessionAttrs(1) | hmac(TPM2B).
  if (auth_area_off + 2 > size) return;
  const uint16_t nonce_size = Read16(buf + auth_area_off);
  if (auth_area_off + 2u + nonce_size > size) return;

  // Refresh nonceTPM for the next command's HMAC.
  if (nonce_size > 0 && nonce_size <= sizeof(g_session.nonce_tpm)) {
    std::memcpy(g_session.nonce_tpm, buf + auth_area_off + 2, nonce_size);
    g_session.nonce_tpm_size = nonce_size;
  }

  // Populate the Name table for commands that return a new transient handle.
  if (attr.out_handle_count == 0) return;
  const uint32_t out_handle = Read32(buf + 10);
  PopulateNameFromResponse(g_session.last_command_code, buf, params_off,
                           params_off + param_size, out_handle);
}

}  // extern "C"

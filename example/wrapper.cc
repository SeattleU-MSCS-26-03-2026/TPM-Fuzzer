#include <harness/tpm_wrapper.h>
#include <libtpms/tpm_library.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

const size_t kMaxBuffers = 4096;
const int kDefaultLocality = 0;

static void SendRawCommand(unsigned char _, const uint8_t* request,
                           size_t request_size, uint8_t* response,
                           size_t* response_size) {
  unsigned char* resp_raw = nullptr;
  uint32_t resp_len = 0;
  uint32_t resp_buf_size = 0;

  TPMLIB_Process(&resp_raw, &resp_len, &resp_buf_size,
                 const_cast<unsigned char*>(request),
                 static_cast<uint32_t>(request_size));

  if (response && response_size && *response_size && resp_raw && resp_len) {
    size_t copy_len = resp_len < *response_size ? resp_len : *response_size;
    std::memcpy(response, resp_raw, copy_len);
    *response_size = copy_len;
  }

  free(resp_raw);
}

void TPMManufactureIfNeeded(void) {
  TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
  TPMLIB_MainInit();
}

void TPMStartup(void) { SendTPM2StartupCommand(); }

void TPMSendCommand(unsigned char locality, struct InBuffer request,
                    struct OutBuffer* response) {
  if (!request.buffer || request.buffer_size == 0 || !response ||
      !response->buffer || response->buffer_size == 0) {
    return;
  }

  std::vector<uint8_t> req(request.buffer,
                           request.buffer + request.buffer_size);

  unsigned char* resp_raw = nullptr;
  uint32_t resp_len = 0;
  uint32_t resp_buf_size = 0;

  TPMLIB_Process(&resp_raw, &resp_len, &resp_buf_size, req.data(),
                 static_cast<uint32_t>(request.buffer_size));

  if (resp_raw && resp_len) {
    size_t copy_len =
        resp_len < response->buffer_size ? resp_len : response->buffer_size;
    std::memcpy(response->buffer, resp_raw, copy_len);
  }

  free(resp_raw);
}

void SendTPM2StartupCommand() {
  static const uint8_t kStartupCmd[] = {
      0x80, 0x01,              // TPM_ST_NO_SESSIONS
      0x00, 0x00, 0x00, 0x0C,  // command size
      0x00, 0x00, 0x01, 0x44,  // TPM2_CC_Startup
      0x00, 0x00               // TPM_SU_CLEAR
  };

  uint8_t resp[kMaxBuffers] = {};
  size_t resp_size = sizeof(resp);
  SendRawCommand(kDefaultLocality, kStartupCmd, sizeof(kStartupCmd), resp,
                 &resp_size);
}

void SendTPM2ShutdownCommand() {
  static const uint8_t kShutdownCmd[] = {
      0x80, 0x01,              // TPM_ST_NO_SESSIONS
      0x00, 0x00, 0x00, 0x0C,  // command size
      0x00, 0x00, 0x01, 0x45,  // TPM2_CC_Shutdown
      0x00, 0x00               // TPM_SU_CLEAR
  };

  uint8_t resp[kMaxBuffers] = {};
  size_t resp_size = sizeof(resp);
  SendRawCommand(kDefaultLocality, kShutdownCmd, sizeof(kShutdownCmd), resp,
                 &resp_size);
}

void TPMShutdown(void) {
  SendTPM2ShutdownCommand();
  TPMLIB_Terminate();
}

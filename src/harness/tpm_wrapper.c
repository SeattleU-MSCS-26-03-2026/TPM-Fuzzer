#include <Platform.h>
#include <harness/session_auth.h>
#include <harness/tpm_wrapper.h>
#include <platform_interface/prototypes/Manufacture_fp.h>
#include <platform_interface/prototypes/_TPM_Hash_End_fp.h>
#include <platform_interface/prototypes/_TPM_Init_fp.h>
#include <prototypes/platform_public_interface.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const size_t kMaxBuffers = 1048576;
const int kDefaultLocality = 0;

const uint8_t kTPM2Startup[] = {
    // TPM2_ST_NO_SESSIONS header
    0x80, 0x01,              // tag: TPM_ST_NO_SESSIONS (0x8001)
    0x00, 0x00, 0x00, 0x0C,  // commandSize: 12 bytes (0x0000000C)
    0x00, 0x00, 0x01, 0x44,  // commandCode: TPM_CC_Startup (0x00000144)

    // Parameters
    0x00, 0x00  // startupType: TPM_SU_CLEAR (0x0000)
};

const uint8_t kTPM2Shutdown[] = {
    // TPM_ST_NO_SESSIONS header
    0x80, 0x01,              // tag: TPM_ST_NO_SESSIONS (0x8001)
    0x00, 0x00, 0x00, 0x0C,  // commandSize: 12 bytes
    0x00, 0x00, 0x01, 0x45,  // commandCode: TPM_CC_Shutdown (0x00000145)

    // Parameters
    0x00, 0x00  // shutdownType: TPM_SU_CLEAR (0x0000)
};

void TPMManufactureIfNeeded(void) {
  _plat__NVEnable(NULL, 0);

  if (_plat__NVNeedsManufacture()) {
    // Perform first-time manufacturing (0 = MANUF_FIRST_TIME)
    if (TPM_Manufacture(0) != 0) {
      fprintf(stderr, "ERROR: Manufacturing failed!\n");
      _plat__NVDisable((void*)TRUE, 0);
      return;
    }
  }
}

void TPMStartup(void) {
  _plat__Signal_PowerOn();

  _plat__Signal_Reset();

  _plat__NVEnable(NULL, 0);

  _plat__SetNvAvail();
}

void TPMSendCommand(unsigned char locality, struct InBuffer request,
                    struct OutBuffer* response) {
  _plat__LocalitySet(locality);

  _plat__RunCommand(request.buffer_size, (unsigned char*)request.buffer,
                    (uint32_t*)&response->buffer_size, &response->buffer);
}

void SendTPM2StartupCommand() {
  struct InBuffer startUpRequest;
  startUpRequest.buffer = kTPM2Startup;
  startUpRequest.buffer_size = sizeof(kTPM2Startup);

  char OutputBuffer[kMaxBuffers];
  struct OutBuffer response;
  response.buffer = (uint8_t*)OutputBuffer;
  response.buffer_size = kMaxBuffers;

  TPMSendCommand(kDefaultLocality, startUpRequest, &response);
}

void SendTPM2ShutdownCommand() {
  struct InBuffer shutdownRequest;
  shutdownRequest.buffer = kTPM2Shutdown;
  shutdownRequest.buffer_size = sizeof(kTPM2Shutdown);

  char OutputBuffer[kMaxBuffers];
  struct OutBuffer response;
  response.buffer = (uint8_t*)OutputBuffer;
  response.buffer_size = kMaxBuffers;

  TPMSendCommand(kDefaultLocality, shutdownRequest, &response);
}

void TPMShutdown(void) {
  _TPM_Hash_End();

  _plat__NvCommit();
  _plat__ClearNvAvail();

  _plat__Signal_PowerOff();

  // Actual reference implementation doesn't remove the NVChip.
  // We want it gone for a fresh start each run.
  // _plat__TearDown();
  _plat__NVDisable((void*)1, 0);
}

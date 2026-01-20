#include <Platform.h>
#include <harness/tpm_wrapper.h>
#include <platform_interface/prototypes/Manufacture_fp.h>
#include <platform_interface/prototypes/_TPM_Hash_End_fp.h>
#include <platform_interface/prototypes/_TPM_Init_fp.h>
#include <prototypes/platform_public_interface.h>
#include <stdio.h>

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

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response) {
  _plat__LocalitySet(locality);

  _plat__RunCommand(request.BufferSize, request.Buffer, &response->BufferSize,
                    &response->Buffer);
}

void TPMShutdown(void) {
  _TPM_Hash_End();

  _plat__NvCommit();
  _plat__ClearNvAvail();

  _plat__Signal_PowerOff();

  _plat__TearDown();
}

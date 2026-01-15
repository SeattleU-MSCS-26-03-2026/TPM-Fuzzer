#include <harness/tpm_wrapper.h>
#include <Platform.h>
#include <platform_interface/prototypes/Manufacture_fp.h>
#include <platform_interface/prototypes/_TPM_Init_fp.h>
#include <platform_interface/prototypes/_TPM_Hash_End_fp.h>
#include <prototypes/platform_public_interface.h>
#include <stdio.h>

void TPMManufactureIfNeeded(void) {
  // Power on and enable NV to check if manufacturing needed
  _plat__Signal_PowerOn();
  _plat__NVEnable(NULL, 0);
  
  // Check if TPM needs manufacturing
  if (_plat__NVNeedsManufacture()) {
    printf("Manufacturing TPM\n");
    
    // Teardown any existing TPM state
    TPM_TearDown();
    
    // Delete existing NV file to ensure clean manufacturing
    _plat__NVDisable((void*)TRUE, 0);
    
    // Re-enable NV for manufacturing
    _plat__NVEnable(NULL, 0);
    
    // Perform first-time manufacturing (0 = MANUF_FIRST_TIME)
    if (TPM_Manufacture(0) != 0) {
      fprintf(stderr, "ERROR: Manufacturing failed!\n");
      _plat__NVDisable((void*)TRUE, 0);
      return;
    }
    
    printf("Manufacturing complete\n");
  } else {
    printf("TPM already manufactured, skipping\n");
  }
}

void TPMStartup(void) {
  printf("Starting up TPM...\n");
  
  // Power on platform
  _plat__Signal_PowerOn();
  
  // Enable NV memory
  _plat__NVEnable(NULL, 0);
  
  // Initialize TPM
  _TPM_Init();
  
  // Make NV memory available
  _plat__SetNvAvail();
  
  printf("TPM startup complete\n");
}

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response) {
  // Set the locality for the command
  _plat__LocalitySet(locality);
  
  // Execute the TPM command directly via Platform API
  _plat__RunCommand(request.BufferSize, request.Buffer, 
                    &response->BufferSize, &response->Buffer);
}

void TPMShutdown(void) {
  printf("Shutting down TPM...\n");
  
  // End hash operations cleanly
  _TPM_Hash_End();
  
  // Commit and disable NV memory
  _plat__NvCommit();
  _plat__ClearNvAvail();
  
  // Signal platform power off
  _plat__Signal_PowerOff();
  
  printf("TPM shutdown complete\n");
}
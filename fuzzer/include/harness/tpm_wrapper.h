#ifndef FUZZER_HARNESS_WRAPPER_H_
#define FUZZER_HARNESS_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct InBuffer {
  const uint8_t* buffer;
  size_t buffer_size;
};

struct OutBuffer {
  uint8_t* buffer;
  size_t buffer_size;
};

// Manufacturing (call once ever, or when you want fresh TPM state)
void TPMManufactureIfNeeded(void);

// Startup (call once per fuzzing session)
void TPMStartup(void);

// Send a command to the TPM
void TPMSendCommand(unsigned char locality, struct InBuffer request,
                    struct OutBuffer* response);

// Shutdown TPM cleanly
void TPMShutdown(void);

#ifdef __cplusplus
}
#endif

#endif  // FUZZER_HARNESS_WRAPPER_H_

#ifndef FUZZER_HARNESS_WRAPPER_H_
#define FUZZER_HARNESS_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

typedef struct {
  unsigned char* Buffer;
  unsigned int BufferSize;
} _IN_BUFFER;

typedef struct {
  unsigned char* Buffer;
  unsigned int BufferSize;
} _OUT_BUFFER;

// Manufacturing (call once ever, or when you want fresh TPM state)
void TPMManufactureIfNeeded(void);

// Startup (call once per fuzzing session)
void TPMStartup(void);

// Send a command to the TPM
void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response);

// Shutdown TPM cleanly
void TPMShutdown(void);

#ifdef __cplusplus
}
#endif

#endif  // FUZZER_HARNESS_WRAPPER_H_

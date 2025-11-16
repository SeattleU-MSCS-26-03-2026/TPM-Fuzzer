#ifndef FUZZER_HARNESS_WRAPPER_H_
#define FUZZER_HARNESS_WRAPPER_H_
#include <stdint.h>
//
#include <TpmTcpProtocol.h>

#ifdef __cplusplus
extern "C" {
#endif

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response);

#ifdef __cplusplus
}
#endif

#endif  // FUZZER_HARNESS_WRAPPER_H_

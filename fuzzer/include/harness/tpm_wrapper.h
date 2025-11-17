#ifndef FUZZER_HARNESS_WRAPPER_H_
#define FUZZER_HARNESS_WRAPPER_H_
#include <stdint.h>
//
#include <TpmTcpProtocol.h>

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response);

#endif  // FUZZER_HARNESS_WRAPPER_H_

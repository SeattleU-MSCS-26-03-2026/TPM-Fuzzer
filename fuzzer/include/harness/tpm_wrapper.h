#ifndef FUZZER_HARNESS_WRAPPER_H_
#define FUZZER_HARNESS_WRAPPER_H_
#include <stdbool.h>
#include <stdint.h>
//
#include <TpmTcpProtocol.h>

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response);

void TPMSignalPowerOn(bool isReset);

void TPMSignalNvOn();

#endif  // FUZZER_HARNESS_WRAPPER_H_

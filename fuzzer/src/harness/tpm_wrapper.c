#include <harness/tpm_wrapper.h>
// This header is not C++ safe
#include <simulatorPrivate.h>

void TPMSendCommand(unsigned char locality, _IN_BUFFER request,
                    _OUT_BUFFER* response) {
  _rpc__Send_Command(locality, request, response);
}

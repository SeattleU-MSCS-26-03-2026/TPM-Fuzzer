#include "src/libfuzzer/libfuzzer_macro.h"
#include "tpm_commands.pb.h"
extern "C" {
#include <harness/tpm_wrapper.h>
}

DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& sequence) { (void)sequence; }
